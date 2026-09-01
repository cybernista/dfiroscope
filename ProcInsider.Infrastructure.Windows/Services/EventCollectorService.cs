using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Collects normalized process lifecycle events from the process tracker.
/// This is the first event source and is designed to be extended later with ETW.
/// </summary>
public class EventCollectorService
{
    private const string DnsOperationalLogName = "Microsoft-Windows-DNS-Client/Operational";
    private const string PowerShellOperationalLogName = "Microsoft-Windows-PowerShell/Operational";
    private const string WindowsPowerShellLogName = "Windows PowerShell";
    private const string SysmonOperationalLogName = "Microsoft-Windows-Sysmon/Operational";
    private const string SecurityLogName = "Security";
    private const int MaxImportedRecordKeysPerSource = 100000;

    private static readonly string[] OtherWindowsLogNames =
    {
        "System",
        "Application",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution"
    };

    private readonly IProcessEventContext _processTracker;
    private readonly ProcessEventStore _runtimeEventStore;
    private readonly ProcessEventStore _securityEventStore;
    private readonly ProcessEventStore _powerShellEventStore;
    private readonly ProcessEventStore _otherWindowsEventStore;
    private readonly ProcessEventStore _sysmonEventStore;
    private readonly EventCollectionOptions _options;
    private readonly PowerShellAuditingService _powerShellAuditingService;
    private readonly SysmonService _sysmonService;
    private readonly Dictionary<string, TcpConnectionSnapshot> _tcpConnections = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sysmonProcessMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly BoundedRecordKeySet _importedSysmonRecords = new(MaxImportedRecordKeysPerSource);
    private readonly BoundedRecordKeySet _importedSecurityRecords = new(MaxImportedRecordKeysPerSource);
    private readonly BoundedRecordKeySet _importedPowerShellRecords = new(MaxImportedRecordKeysPerSource);
    private readonly BoundedRecordKeySet _importedOtherWindowsRecords = new(MaxImportedRecordKeysPerSource);
    private readonly Dictionary<string, EventSourceIngressCounters> _sourceIngressCounters = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sourceIngressLock = new();
    private readonly Dictionary<int, DateTime> _recentPowerShellActivity = new();
    private readonly object _powerShellLock = new();
    private readonly object _sysmonLock = new();
    private readonly object _tcpLock = new();
    private readonly object _sourceHealthLock = new();
    private readonly Dictionary<string, EventSourceHealthSnapshot> _sourceHealth = new(StringComparer.OrdinalIgnoreCase);
    private bool _collectSecurityEvents = true;
    private bool _collectPowerShellEvents = true;
    private bool _collectOtherWindowsEvents = true;
    private bool _collectSysmonEvents = true;

    private CancellationTokenSource? _backgroundCts;
    private Task? _networkMonitorTask;
    private EventLogWatcher? _dnsWatcher;
    private EventLogWatcher? _securityWatcher;
    private EventLogWatcher? _powerShellOperationalWatcher;
    private EventLogWatcher? _windowsPowerShellWatcher;
    private EventLogWatcher? _sysmonWatcher;
    private readonly List<EventLogWatcher> _otherWindowsWatchers = new();
    private FileSystemWatcher? _transcriptWatcher;
    private bool _isRunning;

    public EventCollectorService(
        IProcessEventContext processTracker,
        ProcessEventStore runtimeEventStore,
        ProcessEventStore securityEventStore,
        ProcessEventStore powerShellEventStore,
        ProcessEventStore otherWindowsEventStore,
        ProcessEventStore sysmonEventStore,
        EventCollectionOptions options,
        PowerShellAuditingService powerShellAuditingService,
        SysmonService sysmonService)
    {
        _processTracker = processTracker;
        _runtimeEventStore = runtimeEventStore;
        _securityEventStore = securityEventStore;
        _powerShellEventStore = powerShellEventStore;
        _otherWindowsEventStore = otherWindowsEventStore;
        _sysmonEventStore = sysmonEventStore;
        _options = options;
        _powerShellAuditingService = powerShellAuditingService;
        _sysmonService = sysmonService;
    }

    public IReadOnlyList<EventSourceHealthSnapshot> GetSourceHealthSnapshots()
    {
        lock (_sourceHealthLock)
        {
            return _sourceHealth.Values
                .Select(RefreshSourceHealthDiagnostics)
                .OrderBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    /// <summary>
    /// Starts listening for process lifecycle changes.
    /// </summary>
    public void Start()
    {
        if (_isRunning)
        {
            return;
        }

        if (_options.CollectProcessEvents)
        {
            _processTracker.ProcessChangesDetected += OnProcessChangesDetected;
            SetSourceHealth("Runtime", "Active", "Process lifecycle watcher is active.", enabled: true, active: true);

            if (_options.CollectNetworkEvents)
            {
                _backgroundCts = new CancellationTokenSource();
                SeedTcpConnections();
                _networkMonitorTask = Task.Run(() => MonitorTcpConnectionsAsync(_backgroundCts.Token), _backgroundCts.Token);
            }

            if (_options.CollectDnsEvents)
            {
                TryStartDnsWatcher();
            }
        }
        else
        {
            SetSourceHealth("Runtime", "Disabled", "Runtime process, network, and DNS collection is disabled.", enabled: false, active: false);
        }

        _isRunning = true;

        RefreshSecurityWatcher();
        RefreshPowerShellWatchers();
        RefreshOtherWindowsWatchers();
        RefreshSysmonWatcher();
    }

    /// <summary>
    /// Stops listening for process lifecycle changes.
    /// </summary>
    public void Stop()
    {
        if (!_isRunning)
        {
            return;
        }

            _processTracker.ProcessChangesDetected -= OnProcessChangesDetected;
        _backgroundCts?.Cancel();

        try
        {
            _networkMonitorTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Ignore shutdown timing issues from the background monitor.
        }

        _backgroundCts?.Dispose();
        _backgroundCts = null;
        _networkMonitorTask = null;

        if (_dnsWatcher != null)
        {
            _dnsWatcher.EventRecordWritten -= OnDnsEventRecordWritten;
            _dnsWatcher.Dispose();
            _dnsWatcher = null;
        }

        if (_securityWatcher != null)
        {
            _securityWatcher.EventRecordWritten -= OnSecurityEventRecordWritten;
            _securityWatcher.Dispose();
            _securityWatcher = null;
        }

        if (_powerShellOperationalWatcher != null)
        {
            _powerShellOperationalWatcher.EventRecordWritten -= OnPowerShellOperationalEventRecordWritten;
            _powerShellOperationalWatcher.Dispose();
            _powerShellOperationalWatcher = null;
        }

        if (_windowsPowerShellWatcher != null)
        {
            _windowsPowerShellWatcher.EventRecordWritten -= OnWindowsPowerShellEventRecordWritten;
            _windowsPowerShellWatcher.Dispose();
            _windowsPowerShellWatcher = null;
        }

        foreach (var watcher in _otherWindowsWatchers)
        {
            watcher.EventRecordWritten -= OnOtherWindowsEventRecordWritten;
            watcher.Dispose();
        }

        _otherWindowsWatchers.Clear();

        if (_sysmonWatcher != null)
        {
            _sysmonWatcher.EventRecordWritten -= OnSysmonEventRecordWritten;
            _sysmonWatcher.Dispose();
            _sysmonWatcher = null;
        }

        if (_transcriptWatcher != null)
        {
            _transcriptWatcher.Created -= OnTranscriptFileCreated;
            _transcriptWatcher.Dispose();
            _transcriptWatcher = null;
        }

        lock (_powerShellLock)
        {
            _recentPowerShellActivity.Clear();
        }

        lock (_sysmonLock)
        {
            _sysmonProcessMap.Clear();
            _importedSysmonRecords.Clear();
            _importedSecurityRecords.Clear();
            _importedPowerShellRecords.Clear();
            _importedOtherWindowsRecords.Clear();
        }

        _isRunning = false;
        MarkAllSourcesStopped();
        ClearSourceIngressCounters();
    }

    public void SetSecurityCollectionEnabled(bool enabled)
    {
        _collectSecurityEvents = enabled;
        RefreshSecurityWatcher();
    }

    public void SetPowerShellCollectionEnabled(bool enabled)
    {
        _collectPowerShellEvents = enabled;
        RefreshPowerShellWatchers();
    }

    public void SetOtherWindowsCollectionEnabled(bool enabled)
    {
        _collectOtherWindowsEvents = enabled;
        RefreshOtherWindowsWatchers();
    }

    public void SetSysmonCollectionEnabled(bool enabled)
    {
        _collectSysmonEvents = enabled;
        RefreshSysmonWatcher();
    }

    /// <summary>
    /// Re-evaluates Sysmon watcher state after settings or machine status changes.
    /// </summary>
    public void RefreshSysmonWatcher()
    {
        if (_sysmonWatcher != null)
        {
            _sysmonWatcher.EventRecordWritten -= OnSysmonEventRecordWritten;
            _sysmonWatcher.Dispose();
            _sysmonWatcher = null;
        }

        if (!_isRunning || !_collectSysmonEvents)
        {
            SetSourceHealth("Sysmon", "Disabled", "Sysmon collection is disabled.", _collectSysmonEvents, active: false);
            return;
        }

        try
        {
            var settings = _sysmonService.LoadSettings();
            if (_options.HonorSysmonIntegrationToggle && !settings.IntegrationEnabled)
            {
                SetSourceHealth("Sysmon", "Disabled", $"Sysmon integration is disabled in {ProductIdentity.DisplayName} settings.", enabled: false, active: false);
                return;
            }

            if (!settings.IsServiceStateAvailable)
            {
                SetSourceHealth(
                    "Sysmon",
                    "Unavailable",
                    $"Sysmon service state is inaccessible; it was not treated as not installed. {settings.ServiceStatusDetail} {settings.ServiceError}".Trim(),
                    enabled: true,
                    active: false);
                return;
            }

            if (!settings.IsInstalled)
            {
                SetSourceHealth("Sysmon", "Unavailable", "Sysmon service is not installed.", enabled: true, active: false);
                return;
            }

            if (!settings.IsRunning)
            {
                SetSourceHealth("Sysmon", "Unavailable", "Sysmon service is installed but is not running.", enabled: true, active: false);
                return;
            }

            if (!settings.IsChannelAvailable)
            {
                var status = settings.IsChannelEnabled ? "Degraded" : "Unavailable";
                var detail = string.IsNullOrWhiteSpace(settings.ChannelStatusDetail)
                    ? "Sysmon channel is not available."
                    : settings.ChannelStatusDetail;
                SetSourceHealth("Sysmon", status, detail, enabled: true, active: false, settings.ChannelError);
                return;
            }

            var query = new EventLogQuery(
                SysmonOperationalLogName,
                PathType.LogName,
                "*");

            _sysmonWatcher = new EventLogWatcher(query);
            _sysmonWatcher.EventRecordWritten += OnSysmonEventRecordWritten;
            _sysmonWatcher.Enabled = true;
            SetSourceHealth("Sysmon", "Active", settings.ChannelStatusDetail, enabled: true, active: true);
        }
        catch (Exception ex)
        {
            SetSourceHealth("Sysmon", "Degraded", $"Sysmon watcher unavailable: {ex.Message}", enabled: true, active: false, ex.Message);
        }
    }

    private void RefreshSecurityWatcher()
    {
        if (_securityWatcher != null)
        {
            _securityWatcher.EventRecordWritten -= OnSecurityEventRecordWritten;
            _securityWatcher.Dispose();
            _securityWatcher = null;
        }

        if (!_isRunning || !_collectSecurityEvents)
        {
            SetSourceHealth("Security", "Disabled", "Windows Security log collection is disabled.", _collectSecurityEvents, active: false);
            return;
        }

        TryStartSecurityWatcher();
    }

    private void RefreshPowerShellWatchers()
    {
        if (_powerShellOperationalWatcher != null)
        {
            _powerShellOperationalWatcher.EventRecordWritten -= OnPowerShellOperationalEventRecordWritten;
            _powerShellOperationalWatcher.Dispose();
            _powerShellOperationalWatcher = null;
        }

        if (_windowsPowerShellWatcher != null)
        {
            _windowsPowerShellWatcher.EventRecordWritten -= OnWindowsPowerShellEventRecordWritten;
            _windowsPowerShellWatcher.Dispose();
            _windowsPowerShellWatcher = null;
        }

        if (_transcriptWatcher != null)
        {
            _transcriptWatcher.Created -= OnTranscriptFileCreated;
            _transcriptWatcher.Dispose();
            _transcriptWatcher = null;
        }

        if (!_isRunning || !_collectPowerShellEvents)
        {
            SetSourceHealth("PowerShell", "Disabled", "PowerShell log collection is disabled.", _collectPowerShellEvents, active: false);
            return;
        }

        TryStartPowerShellWatchers();
        TryStartTranscriptWatcher();
        SetPowerShellAggregateHealth();
    }

    private void RefreshOtherWindowsWatchers()
    {
        foreach (var watcher in _otherWindowsWatchers)
        {
            watcher.EventRecordWritten -= OnOtherWindowsEventRecordWritten;
            watcher.Dispose();
        }

        _otherWindowsWatchers.Clear();

        if (!_isRunning || !_collectOtherWindowsEvents)
        {
            SetSourceHealth("WindowsOther", "Disabled", "Other Windows log collection is disabled.", _collectOtherWindowsEvents, active: false);
            return;
        }

        TryStartOtherWindowsWatchers();
    }

    /// <summary>
    /// Imports recent Sysmon events for a selected process so the UI can show records
    /// that happened before the live watcher was started.
    /// </summary>
    public int BackfillSysmonEventsForProcess(ProcessInfo process, TimeSpan lookback, int maxRecords = 1000)
    {
        if (process.ProcessId <= 0)
        {
            return 0;
        }

        if (!_collectSysmonEvents)
        {
            return 0;
        }

        try
        {
            var settings = _sysmonService.LoadSettings();
            if ((_options.HonorSysmonIntegrationToggle && !settings.IntegrationEnabled) || !settings.IsChannelAvailable)
            {
                return 0;
            }

            var milliseconds = Math.Max(1, (long)lookback.TotalMilliseconds);
            var query = new EventLogQuery(
                SysmonOperationalLogName,
                PathType.LogName,
                $"*[System[TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]")
            {
                ReverseDirection = true
            };

            var processKey = process.GetUniqueKey();
            var eventsToAdd = new List<ProcessEventInfo>();
            var scanned = 0;

            using var reader = new EventLogReader(query);
            for (EventRecord? record = reader.ReadEvent();
                 record != null && scanned < maxRecords;
                 record = reader.ReadEvent())
            {
                scanned++;
                using (record)
                {
                    if (!IsCandidateSysmonRecordForProcess(record, process))
                    {
                        continue;
                    }

                    var recordKey = GetSysmonRecordKey(record);
                    if (!string.IsNullOrWhiteSpace(recordKey) && !TryMarkSysmonRecordImported(recordKey))
                    {
                        continue;
                    }

                    var sysmonEvents = TryCreateSysmonEvents(record)
                        .Where(processEvent => processEvent.ProcessKey == processKey)
                        .ToList();

                    if (sysmonEvents.Count == 0 && !string.IsNullOrWhiteSpace(recordKey))
                    {
                        UnmarkSysmonRecordImported(recordKey);
                        continue;
                    }

                    eventsToAdd.AddRange(sysmonEvents);
                }
            }

            if (eventsToAdd.Count > 0)
            {
                _sysmonEventStore.AddEvents(eventsToAdd.OrderBy(e => e.TimestampUtc));
            }

            return eventsToAdd.Count;
        }
        catch
        {
            return 0;
        }
    }

    public int BackfillSecurityEventsForProcess(ProcessInfo process, TimeSpan lookback, int maxRecords = 1000)
    {
        if (!_collectSecurityEvents)
        {
            return 0;
        }

        return BackfillEventLogForProcess(
            process,
            SecurityLogName,
            lookback,
            maxRecords,
            _importedSecurityRecords,
            TryCreateSecurityEvent,
            _securityEventStore);
    }

    public int BackfillPowerShellEventsForProcess(ProcessInfo process, TimeSpan lookback, int maxRecords = 1000)
    {
        if (!_collectPowerShellEvents)
        {
            return 0;
        }

        var count = 0;
        count += BackfillEventLogForProcess(
            process,
            PowerShellOperationalLogName,
            lookback,
            maxRecords,
            _importedPowerShellRecords,
            TryCreatePowerShellEvent,
            _powerShellEventStore);
        count += BackfillEventLogForProcess(
            process,
            WindowsPowerShellLogName,
            lookback,
            maxRecords,
            _importedPowerShellRecords,
            TryCreatePowerShellEvent,
            _powerShellEventStore);
        return count;
    }

    public int BackfillOtherWindowsEventsForProcess(ProcessInfo process, TimeSpan lookback, int maxRecords = 1000)
    {
        if (!_collectOtherWindowsEvents)
        {
            return 0;
        }

        var count = 0;
        foreach (var logName in OtherWindowsLogNames)
        {
            count += BackfillEventLogForProcess(
                process,
                logName,
                lookback,
                maxRecords,
                _importedOtherWindowsRecords,
                TryCreateOtherWindowsEvent,
                _otherWindowsEventStore);
        }

        return count;
    }

    private int BackfillEventLogForProcess(
        ProcessInfo process,
        string logName,
        TimeSpan lookback,
        int maxRecords,
        BoundedRecordKeySet importedRecords,
        Func<EventRecord, ProcessEventInfo?> createEvent,
        ProcessEventStore eventStore)
    {
        if (process.ProcessId <= 0)
        {
            return 0;
        }

        try
        {
            var milliseconds = Math.Max(1, (long)lookback.TotalMilliseconds);
            var query = new EventLogQuery(
                logName,
                PathType.LogName,
                $"*[System[TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]")
            {
                ReverseDirection = true
            };

            var processKey = process.GetUniqueKey();
            var eventsToAdd = new List<ProcessEventInfo>();
            var scanned = 0;

            using var reader = new EventLogReader(query);
            for (EventRecord? record = reader.ReadEvent();
                 record != null && scanned < maxRecords;
                 record = reader.ReadEvent())
            {
                scanned++;
                using (record)
                {
                    if (!IsCandidateWindowsRecordForProcess(record, process))
                    {
                        continue;
                    }

                    var recordKey = GetEventRecordKey(record);
                    if (!string.IsNullOrWhiteSpace(recordKey) && !TryMarkRecordImported(importedRecords, recordKey))
                    {
                        continue;
                    }

                    var processEvent = createEvent(record);
                    if (processEvent == null || processEvent.ProcessKey != processKey)
                    {
                        if (!string.IsNullOrWhiteSpace(recordKey))
                        {
                            UnmarkRecordImported(importedRecords, recordKey);
                        }

                        continue;
                    }

                    eventsToAdd.Add(processEvent);
                }
            }

            if (eventsToAdd.Count > 0)
            {
                eventStore.AddEvents(eventsToAdd.OrderBy(e => e.TimestampUtc));
            }

            return eventsToAdd.Count;
        }
        catch
        {
            return 0;
        }
    }

    private void OnProcessChangesDetected(
        IReadOnlyList<ProcessInfo> newProcesses,
        IReadOnlyList<ProcessInfo> exitedProcesses)
    {
        var events = new List<ProcessEventInfo>();

        foreach (var process in newProcesses)
        {
            events.Add(CreateProcessEvent(process, ProcessEventAction.ProcessStart));
        }

        foreach (var process in exitedProcesses)
        {
            events.Add(CreateProcessEvent(process, ProcessEventAction.ProcessExit));
        }

        if (events.Count > 0)
        {
            _runtimeEventStore.AddEvents(events);
        }
    }

    private async Task MonitorTcpConnectionsAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));

        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            var events = CollectTcpEvents();
            if (events.Count > 0)
            {
                _runtimeEventStore.AddEvents(events);
            }
        }
    }

    private void SeedTcpConnections()
    {
        lock (_tcpLock)
        {
            _tcpConnections.Clear();
            foreach (var connection in GetCurrentTcpSnapshots())
            {
                _tcpConnections[connection.Key] = connection;
            }
        }
    }

    private List<ProcessEventInfo> CollectTcpEvents()
    {
        var now = DateTime.UtcNow;
        var currentConnections = GetCurrentTcpSnapshots();
        var currentByKey = currentConnections.ToDictionary(c => c.Key, StringComparer.OrdinalIgnoreCase);
        var events = new List<ProcessEventInfo>();

        lock (_tcpLock)
        {
            foreach (var snapshot in currentConnections)
            {
                if (!_tcpConnections.ContainsKey(snapshot.Key))
                {
                    var process = _processTracker.GetRunningProcessById(snapshot.ProcessId);
                    if (process != null)
                    {
                        events.Add(CreateNetworkEvent(process, snapshot, ProcessEventAction.Connect, now));
                    }
                }
            }

            foreach (var existing in _tcpConnections.Values)
            {
                if (!currentByKey.ContainsKey(existing.Key))
                {
                    var process = _processTracker.GetRunningProcessById(existing.ProcessId);
                    if (process != null)
                    {
                        events.Add(CreateNetworkEvent(process, existing, ProcessEventAction.Disconnect, now));
                    }
                }
            }

            _tcpConnections.Clear();
            foreach (var snapshot in currentConnections)
            {
                _tcpConnections[snapshot.Key] = snapshot;
            }
        }

        return events;
    }

    private static List<TcpConnectionSnapshot> GetCurrentTcpSnapshots()
    {
        var bufferSize = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AddressFamilyInet, TcpTableOwnerPidAll, 0);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref bufferSize, true, AddressFamilyInet, TcpTableOwnerPidAll, 0);
            if (result != 0)
            {
                return new List<TcpConnectionSnapshot>();
            }

            var rowCount = Marshal.ReadInt32(buffer);
            var rowPointer = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var snapshots = new List<TcpConnectionSnapshot>(rowCount);

            for (var i = 0; i < rowCount; i++)
            {
                var currentPointer = IntPtr.Add(rowPointer, i * rowSize);
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(currentPointer);
                var state = (TcpState)row.state;
                if (state == TcpState.Listen)
                {
                    continue;
                }

                var localIp = new IPAddress(row.localAddr).ToString();
                var remoteIp = new IPAddress(row.remoteAddr).ToString();
                var localPort = ConvertPort(row.localPort);
                var remotePort = ConvertPort(row.remotePort);

                snapshots.Add(new TcpConnectionSnapshot(
                    (int)row.owningPid,
                    localIp,
                    localPort,
                    remoteIp,
                    remotePort,
                    state));
            }

            return snapshots;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void TryStartDnsWatcher()
    {
        try
        {
            var configuration = new EventLogConfiguration(DnsOperationalLogName);
            if (!configuration.IsEnabled)
            {
                SetSourceHealth("Runtime", "Active", $"Process lifecycle watcher is active; optional DNS log {DnsOperationalLogName} is disabled.", enabled: true, active: true);
                return;
            }

            var query = new EventLogQuery(DnsOperationalLogName, PathType.LogName);
            _dnsWatcher = new EventLogWatcher(query);
            _dnsWatcher.EventRecordWritten += OnDnsEventRecordWritten;
            _dnsWatcher.Enabled = true;
            SetSourceHealth("Runtime", "Active", $"Process lifecycle watcher is active; DNS log watcher is active.", enabled: true, active: true);
        }
        catch (Exception ex)
        {
            SetSourceHealth("Runtime", "Active", $"Process lifecycle watcher is active; optional DNS log watcher unavailable: {ex.Message}", enabled: true, active: true);
        }
    }

    private void TryStartPowerShellWatchers()
    {
        if (!_collectPowerShellEvents)
        {
            return;
        }

        TryStartPowerShellOperationalWatcher();
        TryStartWindowsPowerShellWatcher();
    }

    private void TryStartSecurityWatcher()
    {
        try
        {
            if (!_collectSecurityEvents)
            {
                return;
            }

            var configuration = new EventLogConfiguration(SecurityLogName);
            if (!configuration.IsEnabled)
            {
                SetSourceHealth("Security", "Unavailable", "Windows Security log is disabled.", enabled: true, active: false);
                return;
            }

            var query = new EventLogQuery(SecurityLogName, PathType.LogName);
            _securityWatcher = new EventLogWatcher(query);
            _securityWatcher.EventRecordWritten += OnSecurityEventRecordWritten;
            _securityWatcher.Enabled = true;
            SetSourceHealth("Security", "Active", "Watching Windows Security events.", enabled: true, active: true);
        }
        catch (Exception ex)
        {
            SetSourceHealth("Security", "Degraded", $"Windows Security watcher unavailable: {ex.Message}", enabled: true, active: false, ex.Message);
        }
    }

    private bool TryStartPowerShellOperationalWatcher()
    {
        try
        {
            var configuration = new EventLogConfiguration(PowerShellOperationalLogName);
            if (!configuration.IsEnabled)
            {
                return false;
            }

            var query = new EventLogQuery(
                PowerShellOperationalLogName,
                PathType.LogName,
                "*[System[(EventID=4103 or EventID=4104)]]");

            _powerShellOperationalWatcher = new EventLogWatcher(query);
            _powerShellOperationalWatcher.EventRecordWritten += OnPowerShellOperationalEventRecordWritten;
            _powerShellOperationalWatcher.Enabled = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool TryStartWindowsPowerShellWatcher()
    {
        try
        {
            var configuration = new EventLogConfiguration(WindowsPowerShellLogName);
            if (!configuration.IsEnabled)
            {
                return false;
            }

            var query = new EventLogQuery(
                WindowsPowerShellLogName,
                PathType.LogName,
                "*[System[(EventID=400 or EventID=403)]]");

            _windowsPowerShellWatcher = new EventLogWatcher(query);
            _windowsPowerShellWatcher.EventRecordWritten += OnWindowsPowerShellEventRecordWritten;
            _windowsPowerShellWatcher.Enabled = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void TryStartOtherWindowsWatchers()
    {
        if (!_collectOtherWindowsEvents)
        {
            return;
        }

        var activeCount = 0;
        var failedCount = 0;
        foreach (var logName in OtherWindowsLogNames)
        {
            try
            {
                var configuration = new EventLogConfiguration(logName);
                if (!configuration.IsEnabled)
                {
                    failedCount++;
                    continue;
                }

                var query = new EventLogQuery(logName, PathType.LogName);
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += OnOtherWindowsEventRecordWritten;
                watcher.Enabled = true;
                _otherWindowsWatchers.Add(watcher);
                activeCount++;
            }
            catch
            {
                failedCount++;
            }
        }

        if (activeCount > 0)
        {
            var detail = failedCount == 0
                ? $"Watching {activeCount} Windows operational logs."
                : $"Watching {activeCount} Windows operational logs; {failedCount} logs unavailable or disabled.";
            SetSourceHealth("WindowsOther", "Active", detail, enabled: true, active: true);
        }
        else
        {
            SetSourceHealth("WindowsOther", "Unavailable", "No configured Windows operational logs are available.", enabled: true, active: false);
        }
    }

    private bool TryStartTranscriptWatcher()
    {
        try
        {
            if (!_collectPowerShellEvents)
            {
                return false;
            }

            var settings = _powerShellAuditingService.LoadSettings();
            if (!settings.IsAvailable)
            {
                return false;
            }

            if (!settings.TranscriptionEnabled || string.IsNullOrWhiteSpace(settings.TranscriptPath))
            {
                return false;
            }

            if (!Directory.Exists(settings.TranscriptPath))
            {
                return false;
            }

            _transcriptWatcher = new FileSystemWatcher(settings.TranscriptPath, "*.txt")
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime
            };

            _transcriptWatcher.Created += OnTranscriptFileCreated;
            _transcriptWatcher.EnableRaisingEvents = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void SetPowerShellAggregateHealth()
    {
        var activeParts = new List<string>();
        if (_powerShellOperationalWatcher != null)
        {
            activeParts.Add("operational log");
        }

        if (_windowsPowerShellWatcher != null)
        {
            activeParts.Add("classic log");
        }

        if (_transcriptWatcher != null)
        {
            activeParts.Add("transcripts");
        }

        if (activeParts.Count == 0)
        {
            SetSourceHealth("PowerShell", "Unavailable", "No PowerShell logs or transcript folder are available.", enabled: true, active: false);
            return;
        }

        SetSourceHealth(
            "PowerShell",
            activeParts.Count >= 2 ? "Active" : "Degraded",
            $"Watching PowerShell {string.Join(", ", activeParts)}.",
            enabled: true,
            active: true);
    }

    private void SetSourceHealth(
        string source,
        string status,
        string detail,
        bool enabled,
        bool active,
        string? error = null)
    {
        var dedupSnapshot = GetDedupKeySnapshot(source);
        var ingressSnapshot = GetSourceIngressSnapshot(source);
        lock (_sourceHealthLock)
        {
            _sourceHealth[source] = new EventSourceHealthSnapshot(
                source,
                status,
                AppendSourceIngressDetail(source, detail, ingressSnapshot),
                enabled,
                active,
                DateTime.UtcNow,
                error ?? string.Empty,
                dedupSnapshot.Count,
                dedupSnapshot.Capacity,
                dedupSnapshot.Evicted,
                ingressSnapshot.RecordsSeen,
                ingressSnapshot.RecordsMatched,
                ingressSnapshot.DuplicateRecords,
                ingressSnapshot.UnmatchedRecords,
                ingressSnapshot.MalformedRecords);
        }
    }

    private EventSourceHealthSnapshot RefreshSourceHealthDiagnostics(EventSourceHealthSnapshot status)
    {
        var dedupSnapshot = GetDedupKeySnapshot(status.Source);
        var ingressSnapshot = GetSourceIngressSnapshot(status.Source);
        return status with
        {
            Detail = AppendSourceIngressDetail(status.Source, RemoveSourceIngressDetail(status.Detail), ingressSnapshot),
            DedupKeyCount = dedupSnapshot.Count,
            DedupKeyCapacity = dedupSnapshot.Capacity,
            DedupKeysEvicted = dedupSnapshot.Evicted,
            RecordsSeen = ingressSnapshot.RecordsSeen,
            RecordsMatched = ingressSnapshot.RecordsMatched,
            DuplicateRecords = ingressSnapshot.DuplicateRecords,
            UnmatchedRecords = ingressSnapshot.UnmatchedRecords,
            MalformedRecords = ingressSnapshot.MalformedRecords
        };
    }

    private static string AppendSourceIngressDetail(
        string source,
        string detail,
        EventSourceIngressSnapshot ingressSnapshot)
    {
        if (!UsesEventLogIngressDiagnostics(source))
        {
            return detail;
        }

        var baseDetail = RemoveSourceIngressDetail(detail);
        var ingressDetail =
            $"Input records: seen {ingressSnapshot.RecordsSeen:N0}, matched {ingressSnapshot.RecordsMatched:N0}, " +
            $"unmatched {ingressSnapshot.UnmatchedRecords:N0}, duplicate {ingressSnapshot.DuplicateRecords:N0}, malformed {ingressSnapshot.MalformedRecords:N0}.";
        return string.IsNullOrWhiteSpace(baseDetail)
            ? ingressDetail
            : $"{baseDetail} {ingressDetail}";
    }

    private static string RemoveSourceIngressDetail(string detail)
    {
        const string marker = " Input records:";
        var index = detail.IndexOf(marker, StringComparison.Ordinal);
        if (index >= 0)
        {
            return detail[..index].TrimEnd();
        }

        return detail.StartsWith("Input records:", StringComparison.Ordinal)
            ? string.Empty
            : detail;
    }

    private static bool UsesEventLogIngressDiagnostics(string source)
    {
        return string.Equals(source, "Security", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(source, "PowerShell", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(source, "WindowsOther", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(source, "Sysmon", StringComparison.OrdinalIgnoreCase);
    }

    private EventSourceIngressSnapshot GetSourceIngressSnapshot(string source)
    {
        var counters = GetOrCreateSourceIngressCounters(source);
        return new EventSourceIngressSnapshot(
            Interlocked.Read(ref counters.RecordsSeen),
            Interlocked.Read(ref counters.RecordsMatched),
            Interlocked.Read(ref counters.DuplicateRecords),
            Interlocked.Read(ref counters.UnmatchedRecords),
            Interlocked.Read(ref counters.MalformedRecords));
    }

    private void IncrementSourceRecordsSeen(string source)
    {
        Interlocked.Increment(ref GetOrCreateSourceIngressCounters(source).RecordsSeen);
    }

    private void IncrementSourceRecordsMatched(string source, long count = 1)
    {
        if (count <= 0)
        {
            return;
        }

        Interlocked.Add(ref GetOrCreateSourceIngressCounters(source).RecordsMatched, count);
    }

    private void IncrementSourceDuplicateRecords(string source)
    {
        Interlocked.Increment(ref GetOrCreateSourceIngressCounters(source).DuplicateRecords);
    }

    private void IncrementSourceUnmatchedRecords(string source)
    {
        Interlocked.Increment(ref GetOrCreateSourceIngressCounters(source).UnmatchedRecords);
    }

    private void IncrementSourceMalformedRecords(string source)
    {
        Interlocked.Increment(ref GetOrCreateSourceIngressCounters(source).MalformedRecords);
    }

    private EventSourceIngressCounters GetOrCreateSourceIngressCounters(string source)
    {
        lock (_sourceIngressLock)
        {
            if (!_sourceIngressCounters.TryGetValue(source, out var counters))
            {
                counters = new EventSourceIngressCounters();
                _sourceIngressCounters[source] = counters;
            }

            return counters;
        }
    }

    private void ClearSourceIngressCounters()
    {
        lock (_sourceIngressLock)
        {
            _sourceIngressCounters.Clear();
        }
    }

    private RecordKeySetSnapshot GetDedupKeySnapshot(string source)
    {
        return source switch
        {
            "Security" => _importedSecurityRecords.GetSnapshot(),
            "PowerShell" => _importedPowerShellRecords.GetSnapshot(),
            "WindowsOther" => _importedOtherWindowsRecords.GetSnapshot(),
            "Sysmon" => _importedSysmonRecords.GetSnapshot(),
            _ => default
        };
    }

    private void MarkAllSourcesStopped()
    {
        lock (_sourceHealthLock)
        {
            foreach (var entry in _sourceHealth.Values.ToList())
            {
                _sourceHealth[entry.Source] = entry with
                {
                    Status = "Stopped",
                    Detail = $"{entry.Source} collection is stopped.",
                    IsActive = false,
                    UpdatedUtc = DateTime.UtcNow
                };
            }
        }
    }

    private void OnDnsEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException != null || e.EventRecord == null)
        {
            return;
        }

        try
        {
            var dnsEvent = TryCreateDnsEvent(e.EventRecord);
            if (dnsEvent != null)
            {
                _runtimeEventStore.AddEvent(dnsEvent);
            }
        }
        catch
        {
            // Ignore malformed or unsupported DNS log records.
        }
        finally
        {
            e.EventRecord.Dispose();
        }
    }

    private void OnPowerShellOperationalEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        OnPowerShellEventRecordWritten(e);
    }

    private void OnSecurityEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        const string source = "Security";
        if (e.EventException != null || e.EventRecord == null)
        {
            IncrementSourceMalformedRecords(source);
            return;
        }

        string? recordKey = null;
        var recordMarked = false;
        try
        {
            IncrementSourceRecordsSeen(source);
            recordKey = GetEventRecordKey(e.EventRecord);
            if (!string.IsNullOrWhiteSpace(recordKey) && !TryMarkRecordImported(_importedSecurityRecords, recordKey))
            {
                IncrementSourceDuplicateRecords(source);
                return;
            }

            recordMarked = !string.IsNullOrWhiteSpace(recordKey);
            var securityEvent = TryCreateSecurityEvent(e.EventRecord);
            if (securityEvent != null)
            {
                IncrementSourceRecordsMatched(source);
                _securityEventStore.AddEvent(securityEvent);
            }
            else
            {
                IncrementSourceUnmatchedRecords(source);
                if (!string.IsNullOrWhiteSpace(recordKey))
                {
                    UnmarkRecordImported(_importedSecurityRecords, recordKey);
                }
            }
        }
        catch
        {
            IncrementSourceMalformedRecords(source);
            if (recordMarked && !string.IsNullOrWhiteSpace(recordKey))
            {
                UnmarkRecordImported(_importedSecurityRecords, recordKey);
            }

            // Ignore malformed or unsupported Security log records.
        }
        finally
        {
            e.EventRecord.Dispose();
        }
    }

    private void OnWindowsPowerShellEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        OnPowerShellEventRecordWritten(e);
    }

    private void OnPowerShellEventRecordWritten(EventRecordWrittenEventArgs e)
    {
        const string source = "PowerShell";
        if (e.EventException != null || e.EventRecord == null)
        {
            IncrementSourceMalformedRecords(source);
            return;
        }

        string? recordKey = null;
        var recordMarked = false;
        try
        {
            IncrementSourceRecordsSeen(source);
            recordKey = GetEventRecordKey(e.EventRecord);
            if (!string.IsNullOrWhiteSpace(recordKey) && !TryMarkRecordImported(_importedPowerShellRecords, recordKey))
            {
                IncrementSourceDuplicateRecords(source);
                return;
            }

            recordMarked = !string.IsNullOrWhiteSpace(recordKey);
            var powerShellEvent = TryCreatePowerShellEvent(e.EventRecord);
            if (powerShellEvent != null)
            {
                IncrementSourceRecordsMatched(source);
                _powerShellEventStore.AddEvent(powerShellEvent);
            }
            else
            {
                IncrementSourceUnmatchedRecords(source);
                if (!string.IsNullOrWhiteSpace(recordKey))
                {
                    UnmarkRecordImported(_importedPowerShellRecords, recordKey);
                }
            }
        }
        catch
        {
            IncrementSourceMalformedRecords(source);
            if (recordMarked && !string.IsNullOrWhiteSpace(recordKey))
            {
                UnmarkRecordImported(_importedPowerShellRecords, recordKey);
            }

            // Ignore malformed or unsupported PowerShell log records.
        }
        finally
        {
            e.EventRecord.Dispose();
        }
    }

    private void OnOtherWindowsEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        const string source = "WindowsOther";
        if (e.EventException != null || e.EventRecord == null)
        {
            IncrementSourceMalformedRecords(source);
            return;
        }

        string? recordKey = null;
        var recordMarked = false;
        try
        {
            IncrementSourceRecordsSeen(source);
            recordKey = GetEventRecordKey(e.EventRecord);
            if (!string.IsNullOrWhiteSpace(recordKey) && !TryMarkRecordImported(_importedOtherWindowsRecords, recordKey))
            {
                IncrementSourceDuplicateRecords(source);
                return;
            }

            recordMarked = !string.IsNullOrWhiteSpace(recordKey);
            var windowsEvent = TryCreateOtherWindowsEvent(e.EventRecord);
            if (windowsEvent != null)
            {
                IncrementSourceRecordsMatched(source);
                _otherWindowsEventStore.AddEvent(windowsEvent);
            }
            else
            {
                IncrementSourceUnmatchedRecords(source);
                if (!string.IsNullOrWhiteSpace(recordKey))
                {
                    UnmarkRecordImported(_importedOtherWindowsRecords, recordKey);
                }
            }
        }
        catch
        {
            IncrementSourceMalformedRecords(source);
            if (recordMarked && !string.IsNullOrWhiteSpace(recordKey))
            {
                UnmarkRecordImported(_importedOtherWindowsRecords, recordKey);
            }

            // Ignore malformed or unsupported Windows log records.
        }
        finally
        {
            e.EventRecord.Dispose();
        }
    }

    private void OnSysmonEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        const string source = "Sysmon";
        if (e.EventException != null || e.EventRecord == null)
        {
            IncrementSourceMalformedRecords(source);
            return;
        }

        string? recordKey = null;
        var recordMarked = false;
        try
        {
            IncrementSourceRecordsSeen(source);
            recordKey = GetSysmonRecordKey(e.EventRecord);
            if (!string.IsNullOrWhiteSpace(recordKey) && !TryMarkSysmonRecordImported(recordKey))
            {
                IncrementSourceDuplicateRecords(source);
                return;
            }

            recordMarked = !string.IsNullOrWhiteSpace(recordKey);
            var sysmonEvents = TryCreateSysmonEvents(e.EventRecord);
            if (sysmonEvents.Count > 0)
            {
                IncrementSourceRecordsMatched(source, sysmonEvents.Count);
                _sysmonEventStore.AddEvents(sysmonEvents);
            }
            else
            {
                IncrementSourceUnmatchedRecords(source);
                if (!string.IsNullOrWhiteSpace(recordKey))
                {
                    UnmarkSysmonRecordImported(recordKey);
                }
            }
        }
        catch
        {
            IncrementSourceMalformedRecords(source);
            if (recordMarked && !string.IsNullOrWhiteSpace(recordKey))
            {
                UnmarkSysmonRecordImported(recordKey);
            }

            // Ignore malformed or unsupported Sysmon log records.
        }
        finally
        {
            e.EventRecord.Dispose();
        }
    }

    private void OnTranscriptFileCreated(object sender, FileSystemEventArgs e)
    {
        const string source = "PowerShell";
        try
        {
            IncrementSourceRecordsSeen(source);
            var transcriptEvent = TryCreateTranscriptEvent(e.FullPath);
            if (transcriptEvent != null)
            {
                IncrementSourceRecordsMatched(source);
                _powerShellEventStore.AddEvent(transcriptEvent);
            }
            else
            {
                IncrementSourceUnmatchedRecords(source);
            }
        }
        catch
        {
            IncrementSourceMalformedRecords(source);
            // Ignore transcript files we cannot inspect.
        }
    }

    private ProcessEventInfo? TryCreateDnsEvent(EventRecord eventRecord)
    {
        var xml = eventRecord.ToXml();
        var processId = ExtractIntFromXml(xml, "ProcessId");
        if (processId <= 0)
        {
            processId = eventRecord.ProcessId ?? 0;
        }

        if (processId <= 0)
        {
            return null;
        }

        var timestamp = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
        var process = _processTracker.GetBestProcessMatch(processId, null, timestamp);
        if (process == null)
        {
            return null;
        }

        var queryName = ExtractStringFromXml(xml, "QueryName");
        if (string.IsNullOrWhiteSpace(queryName))
        {
            queryName = ExtractStringFromXml(xml, "Name");
        }

        if (string.IsNullOrWhiteSpace(queryName))
        {
            return null;
        }

        return new ProcessEventInfo
        {
            TimestampUtc = timestamp,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            EventCode = eventRecord.Id,
            Category = ProcessEventCategory.Dns,
            Action = ProcessEventAction.DnsQuery,
            Target = queryName,
            Summary = $"DNS query: {queryName}",
            Details = $"DNS Client event ID: {eventRecord.Id}; User: {process.UserName}",
            IsInteresting = true
        };
    }

    private ProcessEventInfo? TryCreateSecurityEvent(EventRecord eventRecord)
    {
        var xml = eventRecord.ToXml();
        var processId = ExtractWindowsProcessId(xml, includeExecutionProcessId: false);
        if (processId <= 0)
        {
            return null;
        }

        var process = ResolveTrackedProcess(processId);
        if (process == null)
        {
            return null;
        }

        var target = FirstNonEmpty(
            ExtractStringFromXml(xml, "NewProcessName"),
            ExtractStringFromXml(xml, "ProcessName"),
            ExtractStringFromXml(xml, "ObjectName"),
            ExtractStringFromXml(xml, "TargetObject"),
            process.ProcessPath,
            process.ProcessName);
        var subjectUser = FirstNonEmpty(
            ExtractStringFromXml(xml, "SubjectUserName"),
            ExtractStringFromXml(xml, "TargetUserName"),
            process.UserName);
        var logName = GetEventLogName(eventRecord);

        return new ProcessEventInfo
        {
            TimestampUtc = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            EventCode = eventRecord.Id,
            Category = ProcessEventCategory.Security,
            Action = ProcessEventAction.SecurityAudit,
            Target = target,
            Summary = $"{logName} event {eventRecord.Id}: {TrimSingleLine(FirstNonEmpty(target, SafeFormatDescription(eventRecord)), 140)}",
            Details = BuildEventRecordContent(
                eventRecord,
                xml,
                $"Log: {logName}",
                $"Provider: {eventRecord.ProviderName}",
                $"Process: {process.ProcessName} (PID: {process.ProcessId})",
                $"User: {subjectUser}",
                $"Target: {target}"),
            RiskFlags = "security",
            IsInteresting = true
        };
    }

    private ProcessEventInfo? TryCreateOtherWindowsEvent(EventRecord eventRecord)
    {
        var xml = eventRecord.ToXml();
        var timestampUtc = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
        var process = ResolveWindowsEventProcess(eventRecord, xml, timestampUtc);
        if (process == null)
        {
            return null;
        }

        var logName = GetEventLogName(eventRecord);
        var target = FirstNonEmpty(
            ExtractStringFromXml(xml, "ProcessName"),
            ExtractStringFromXml(xml, "ProcessPath"),
            ExtractStringFromXml(xml, "Application"),
            ExtractStringFromXml(xml, "ApplicationPath"),
            ExtractStringFromXml(xml, "FilePath"),
            ExtractStringFromXml(xml, "FileName"),
            ExtractStringFromXml(xml, "Image"),
            ExtractStringFromXml(xml, "Path"),
            ExtractStringFromXml(xml, "TaskName"),
            ExtractStringFromXml(xml, "Name"),
            ExtractStringFromXml(xml, "ServiceFileName"),
            ExtractStringFromXml(xml, "ServiceName"),
            ExtractStringFromXml(xml, "param1"),
            ExtractStringFromXml(xml, "param2"),
            ExtractStringFromXml(xml, "TargetUserName"),
            eventRecord.ProviderName,
            process.ProcessPath,
            process.ProcessName);

        return new ProcessEventInfo
        {
            TimestampUtc = timestampUtc,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            EventCode = eventRecord.Id,
            Category = ProcessEventCategory.Windows,
            Action = ProcessEventAction.WindowsEvent,
            Target = target,
            Summary = $"{logName} event {eventRecord.Id}: {TrimSingleLine(FirstNonEmpty(target, SafeFormatDescription(eventRecord)), 140)}",
            Details = BuildEventRecordContent(
                eventRecord,
                xml,
                $"Log: {logName}",
                $"Provider: {eventRecord.ProviderName}",
                $"Process: {process.ProcessName} (PID: {process.ProcessId})",
                $"Target: {target}"),
            RiskFlags = "windows",
            IsInteresting = true
        };
    }

    private ProcessEventInfo? TryCreatePowerShellEvent(EventRecord eventRecord)
    {
        var xml = eventRecord.ToXml();
        var processId = eventRecord.ProcessId ?? ExtractExecutionProcessId(xml);
        if (processId <= 0)
        {
            return null;
        }

        var process = ResolveTrackedProcess(processId);
        if (process == null)
        {
            return null;
        }

        TrackPowerShellActivity(process.ProcessId, eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow);

        return eventRecord.Id switch
        {
            4103 => CreatePowerShellCommandEvent(process, eventRecord, xml),
            4104 => CreatePowerShellScriptBlockEvent(process, eventRecord, xml),
            400 => CreatePowerShellEngineEvent(process, eventRecord, xml, ProcessEventAction.PowerShellEngineStart),
            403 => CreatePowerShellEngineEvent(process, eventRecord, xml, ProcessEventAction.PowerShellEngineStop),
            _ => null
        };
    }

    private List<ProcessEventInfo> TryCreateSysmonEvents(EventRecord eventRecord)
    {
        var xml = eventRecord.ToXml();
        var eventId = eventRecord.Id;
        var useSourceProcess = eventId is 8 or 10;
        var processGuid = useSourceProcess
            ? ExtractStringFromXml(xml, "SourceProcessGUID")
            : ExtractStringFromXml(xml, "ProcessGuid");
        var processId = useSourceProcess
            ? ExtractIntFromXml(xml, "SourceProcessId")
            : ExtractIntFromXml(xml, "ProcessId");
        var image = useSourceProcess
            ? ExtractStringFromXml(xml, "SourceImage")
            : ExtractStringFromXml(xml, "Image");
        var commandLine = ExtractStringFromXml(xml, "CommandLine");
        var eventTimeUtc = ExtractSysmonUtcTime(xml) ?? eventRecord.TimeCreated?.ToUniversalTime();
        if (processId <= 0)
        {
            processId = eventRecord.ProcessId ?? 0;
        }

        if (processId <= 0)
        {
            return new List<ProcessEventInfo> { CreateGenericSysmonEventForProvider(eventRecord, xml) };
        }

        ProcessInfo? process;
        if (eventId == 1)
        {
            process = _processTracker.TrackExternalProcess(
                BuildProcessInfoFromSysmonCreate(xml, eventTimeUtc),
                "SysmonProcessCreate",
                ProcessObservationKind.SysmonProcessCreate);
        }
        else
        {
            process = ResolveSysmonTrackedProcess(processGuid, processId, image, eventTimeUtc, image, commandLine);
        }

        if (process != null && eventId == 5)
        {
            process = _processTracker.TrackExternalProcess(
                BuildProcessInfoFromSysmonTerminate(process, processGuid, eventTimeUtc),
                "SysmonProcessTerminate",
                ProcessObservationKind.SysmonProcessTerminate);
        }

        if (process == null)
        {
            return new List<ProcessEventInfo> { CreateGenericSysmonEventForProvider(eventRecord, xml) };
        }

        var primaryEvent = eventRecord.Id switch
        {
            1 => CreateSysmonProcessCreateEvent(process, eventRecord, xml),
            3 => CreateSysmonNetworkEvent(process, eventRecord, xml),
            5 => CreateSysmonProcessTerminateEvent(process, eventRecord, xml),
            7 => CreateSysmonImageLoadEvent(process, eventRecord, xml),
            8 => CreateSysmonCreateRemoteThreadEvent(process, eventRecord, xml),
            9 => CreateSysmonRawAccessReadEvent(process, eventRecord, xml),
            10 => CreateSysmonProcessAccessEvent(process, eventRecord, xml),
            11 => CreateSysmonFileCreateEvent(process, eventRecord, xml),
            12 => CreateSysmonRegistryCreateDeleteEvent(process, eventRecord, xml),
            13 => CreateSysmonRegistrySetValueEvent(process, eventRecord, xml),
            14 => CreateSysmonRegistryRenameEvent(process, eventRecord, xml),
            15 => CreateSysmonFileCreateStreamHashEvent(process, eventRecord, xml),
            17 => CreateSysmonPipeEvent(process, eventRecord, xml, ProcessEventAction.PipeCreated),
            18 => CreateSysmonPipeEvent(process, eventRecord, xml, ProcessEventAction.PipeConnected),
            19 => CreateSysmonWmiEvent(process, eventRecord, xml, ProcessEventAction.WmiFilter),
            20 => CreateSysmonWmiEvent(process, eventRecord, xml, ProcessEventAction.WmiConsumer),
            21 => CreateSysmonWmiEvent(process, eventRecord, xml, ProcessEventAction.WmiBinding),
            22 => CreateSysmonDnsQueryEvent(process, eventRecord, xml),
            25 => CreateSysmonProcessTamperingEvent(process, eventRecord, xml),
            26 => CreateSysmonFileDeleteEvent(process, eventRecord, xml),
            _ => CreateGenericSysmonEvent(process, eventRecord, xml)
        };

        var events = new List<ProcessEventInfo> { primaryEvent };
        AddTargetProcessEventIfAvailable(events, primaryEvent, eventRecord, xml);
        return events;
    }

    private ProcessEventInfo? TryCreateTranscriptEvent(string transcriptPath)
    {
        if (!File.Exists(transcriptPath))
        {
            return null;
        }

        var fileInfo = new FileInfo(transcriptPath);
        var timestampUtc = fileInfo.CreationTimeUtc != DateTime.MinValue
            ? fileInfo.CreationTimeUtc
            : DateTime.UtcNow;

        var process = ResolveTranscriptProcess(timestampUtc);
        if (process == null)
        {
            return null;
        }

        TrackPowerShellActivity(process.ProcessId, timestampUtc);

        return new ProcessEventInfo
        {
            TimestampUtc = timestampUtc,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            Category = ProcessEventCategory.PowerShell,
            Action = ProcessEventAction.PowerShellTranscript,
            Target = transcriptPath,
            Summary = $"PowerShell transcript started: {Path.GetFileName(transcriptPath)}",
            Details = BuildMultilineDetails(
                $"Transcript path: {transcriptPath}",
                $"Size: {fileInfo.Length} bytes",
                $"User: {process.UserName}",
                $"Process: {process.ProcessName} (PID: {process.ProcessId})",
                $"Command line: {process.CommandLine}"),
            IsInteresting = true
        };
    }

    private ProcessEventInfo CreatePowerShellScriptBlockEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var scriptBlockText = ExtractStringFromXml(xml, "ScriptBlockText");
        var scriptBlockId = ExtractStringFromXml(xml, "ScriptBlockId");
        var path = ExtractStringFromXml(xml, "Path");

        var target = !string.IsNullOrWhiteSpace(path) ? path : scriptBlockId ?? process.ProcessName;
        var summaryText = string.IsNullOrWhiteSpace(scriptBlockText)
            ? "PowerShell script block executed."
            : $"PowerShell script block: {TrimSingleLine(scriptBlockText, 120)}";

        return CreatePowerShellEvent(
            process,
            eventRecord,
            ProcessEventAction.PowerShellScriptBlock,
            target,
            summaryText,
            BuildAuditEventDetails(
                eventRecord,
                xml,
                $"ScriptBlockId: {scriptBlockId}",
                $"Path: {path}",
                $"User: {process.UserName}",
                $"Command line: {process.CommandLine}",
                "",
                "Script Block Text:",
                scriptBlockText),
            "script-block");
    }

    private ProcessEventInfo CreatePowerShellCommandEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var payload = ExtractStringFromXml(xml, "Payload");
        var contextInfo = ExtractStringFromXml(xml, "ContextInfo");
        var commandName = ExtractContextValue(contextInfo, "Command Name");
        var hostApplication = ExtractContextValue(contextInfo, "Host Application");
        var scriptName = ExtractContextValue(contextInfo, "Script Name");
        var target = FirstNonEmpty(commandName, scriptName, hostApplication, process.ProcessName);

        var summary = !string.IsNullOrWhiteSpace(payload)
            ? $"PowerShell command: {TrimSingleLine(payload, 120)}"
            : $"PowerShell command invocation: {target}";

        return CreatePowerShellEvent(
            process,
            eventRecord,
            ProcessEventAction.PowerShellCommand,
            target,
            summary,
            BuildAuditEventDetails(
                eventRecord,
                xml,
                $"Host application: {hostApplication}",
                $"Script: {scriptName}",
                $"User: {process.UserName}",
                "",
                "Context:",
                contextInfo,
                "",
                "Payload:",
                payload),
            "module-logging");
    }

    private ProcessEventInfo CreatePowerShellEngineEvent(
        ProcessInfo process,
        EventRecord eventRecord,
        string xml,
        ProcessEventAction action)
    {
        var detailsBlob = ExtractUnnamedDataValue(xml, 2);
        var hostApplication = ExtractContextValue(detailsBlob, "HostApplication");
        var engineState = ExtractContextValue(detailsBlob, "NewEngineState");
        var target = FirstNonEmpty(hostApplication, process.ProcessPath, process.ProcessName);
        var isStart = action == ProcessEventAction.PowerShellEngineStart;

        return CreatePowerShellEvent(
            process,
            eventRecord,
            action,
            target,
            isStart
                ? $"PowerShell engine started: {process.ProcessName}"
                : $"PowerShell engine stopped: {process.ProcessName}",
            BuildAuditEventDetails(
                eventRecord,
                xml,
                $"Engine state: {engineState}",
                $"Host application: {hostApplication}",
                $"User: {process.UserName}",
                "",
                "Details:",
                detailsBlob),
            "engine");
    }

    private ProcessEventInfo CreatePowerShellEvent(
        ProcessInfo process,
        EventRecord eventRecord,
        ProcessEventAction action,
        string target,
        string summary,
        string details,
        string riskFlags)
    {
        return new ProcessEventInfo
        {
            TimestampUtc = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            EventCode = eventRecord.Id,
            Category = ProcessEventCategory.PowerShell,
            Action = action,
            Target = target,
            Summary = summary,
            Details = details,
            RiskFlags = riskFlags,
            IsInteresting = true
        };
    }

    private static ProcessEventInfo CreateProcessEvent(ProcessInfo process, ProcessEventAction action)
    {
        var isStart = action == ProcessEventAction.ProcessStart;
        var timestamp = isStart
            ? process.StartTime ?? DateTime.Now
            : process.EndTime ?? DateTime.Now;

        var target = string.IsNullOrWhiteSpace(process.ProcessPath) || process.ProcessPath == "<not available>"
            ? process.ProcessName
            : process.ProcessPath;

        return new ProcessEventInfo
        {
            TimestampUtc = timestamp.ToUniversalTime(),
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            Category = ProcessEventCategory.Process,
            Action = action,
            Target = target,
            Summary = isStart
                ? $"Process started: {process.ProcessName} (PID: {process.ProcessId})"
                : $"Process exited: {process.ProcessName} (PID: {process.ProcessId})",
            Details = BuildDetails(process),
            IsInteresting = false
        };
    }

    private static string BuildDetails(ProcessInfo process)
    {
        return $"Parent PID: {process.ParentProcessId}; User: {process.UserName}; Command line: {process.CommandLine}";
    }

    private ProcessEventInfo CreateSysmonProcessCreateEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var commandLine = ExtractStringFromXml(xml, "CommandLine");
        var parentImage = ExtractStringFromXml(xml, "ParentImage");
        var parentCommandLine = ExtractStringFromXml(xml, "ParentCommandLine");
        var originalFileName = ExtractStringFromXml(xml, "OriginalFileName");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var parentProcessGuid = ExtractStringFromXml(xml, "ParentProcessGuid");
        var target = FirstNonEmpty(image, process.ProcessPath, process.ProcessName);

        TrackSysmonProcess(processGuid, process);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Process,
            ProcessEventAction.ProcessStart,
            target,
            $"Sysmon process create: {process.ProcessName} (PID: {process.ProcessId})",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"Command line: {commandLine}",
                $"OriginalFileName: {originalFileName}",
                $"ProcessGuid: {processGuid}",
                $"Parent image: {parentImage}",
                $"Parent command line: {parentCommandLine}",
                $"ParentProcessGuid: {parentProcessGuid}",
                $"User: {process.UserName}"),
            "sysmon");
    }

    private static ProcessInfo BuildProcessInfoFromSysmonCreate(string xml, DateTime? eventTimeUtc)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processName = Path.GetFileName(image);
        var user = ExtractStringFromXml(xml, "User");
        var hashes = ExtractStringFromXml(xml, "Hashes");

        return new ProcessInfo
        {
            ProcessId = ExtractIntFromXml(xml, "ProcessId"),
            ProcessGuid = ExtractStringFromXml(xml, "ProcessGuid") ?? string.Empty,
            ProcessName = string.IsNullOrWhiteSpace(processName) ? "<unknown>" : processName,
            ProcessPath = string.IsNullOrWhiteSpace(image) ? "<not available>" : image,
            CommandLine = ExtractStringFromXml(xml, "CommandLine") ?? "<not available>",
            ParentProcessId = ExtractIntFromXml(xml, "ParentProcessId"),
            ParentProcessName = Path.GetFileName(ExtractStringFromXml(xml, "ParentImage")) ?? "<unknown>",
            UserName = string.IsNullOrWhiteSpace(user) ? "<not available>" : user,
            SessionId = ExtractIntFromXml(xml, "TerminalSessionId"),
            StartTime = eventTimeUtc?.ToLocalTime(),
            CompanyName = ExtractStringFromXml(xml, "Company") ?? "<not available>",
            FileDescription = ExtractStringFromXml(xml, "Description") ?? "<not available>",
            Sha256Hash = ExtractHashValue(hashes, "SHA256") ?? "<not available>",
            Status = ProcessStatus.Running
        };
    }

    private static ProcessInfo BuildProcessInfoFromSysmonTerminate(
        ProcessInfo process,
        string? processGuid,
        DateTime? eventTimeUtc)
        => new()
        {
            ProcessId = process.ProcessId,
            ProcessGuid = FirstNonEmpty(processGuid, process.ProcessGuid),
            ProcessKey = process.GetUniqueKey(),
            ProcessName = process.ProcessName,
            ProcessPath = process.ProcessPath,
            CommandLine = process.CommandLine,
            ParentProcessId = process.ParentProcessId,
            ParentProcessKey = process.ParentProcessKey,
            ParentProcessName = process.ParentProcessName,
            UserName = process.UserName,
            SessionId = process.SessionId,
            StartTime = process.StartTime,
            EndTime = (eventTimeUtc ?? DateTime.UtcNow).ToLocalTime(),
            Status = ProcessStatus.Exited,
            Architecture = process.Architecture,
            CompanyName = process.CompanyName,
            FileDescription = process.FileDescription,
            Sha256Hash = process.Sha256Hash
        };

    private ProcessEventInfo CreateSysmonProcessTerminateEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var target = FirstNonEmpty(image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Process,
            ProcessEventAction.ProcessExit,
            target,
            $"Sysmon process terminate: {process.ProcessName} (PID: {process.ProcessId})",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {process.UserName}",
                $"Command line: {process.CommandLine}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonImageLoadEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var imageLoaded = ExtractStringFromXml(xml, "ImageLoaded");
        var hashes = ExtractStringFromXml(xml, "Hashes");
        var signature = ExtractStringFromXml(xml, "Signature");
        var signed = ExtractStringFromXml(xml, "Signed");
        var target = FirstNonEmpty(imageLoaded, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Process,
            ProcessEventAction.ImageLoad,
            target,
            $"Sysmon image loaded: {Path.GetFileName(target)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"ImageLoaded: {imageLoaded}",
                $"Hashes: {hashes}",
                $"Signed: {signed}",
                $"Signature: {signature}",
                $"User: {process.UserName}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonCreateRemoteThreadEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var sourceProcessGuid = ExtractStringFromXml(xml, "SourceProcessGUID");
        var sourceImage = ExtractStringFromXml(xml, "SourceImage");
        var targetProcessGuid = ExtractStringFromXml(xml, "TargetProcessGUID");
        var targetProcessId = ExtractStringFromXml(xml, "TargetProcessId");
        var targetImage = ExtractStringFromXml(xml, "TargetImage");
        var newThreadId = ExtractStringFromXml(xml, "NewThreadId");
        var startAddress = ExtractStringFromXml(xml, "StartAddress");
        var startModule = ExtractStringFromXml(xml, "StartModule");
        var startFunction = ExtractStringFromXml(xml, "StartFunction");
        var target = FirstNonEmpty(targetImage, targetProcessId, sourceImage, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            sourceProcessGuid,
            ProcessEventCategory.Process,
            ProcessEventAction.CreateRemoteThread,
            target,
            $"Sysmon remote thread: {Path.GetFileName(sourceImage ?? process.ProcessName)} -> {Path.GetFileName(target)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"SourceImage: {sourceImage}",
                $"SourceProcessGUID: {sourceProcessGuid}",
                $"TargetImage: {targetImage}",
                $"TargetProcessGUID: {targetProcessGuid}",
                $"TargetProcessId: {targetProcessId}",
                $"NewThreadId: {newThreadId}",
                $"StartAddress: {startAddress}",
                $"StartModule: {startModule}",
                $"StartFunction: {startFunction}",
                $"User: {process.UserName}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonRawAccessReadEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var device = ExtractStringFromXml(xml, "Device");
        var target = FirstNonEmpty(device, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.File,
            ProcessEventAction.RawAccessRead,
            target,
            $"Sysmon raw access read: {target}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"Device: {device}",
                $"User: {process.UserName}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonProcessAccessEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var sourceProcessGuid = ExtractStringFromXml(xml, "SourceProcessGUID");
        var sourceImage = ExtractStringFromXml(xml, "SourceImage");
        var sourceProcessId = ExtractStringFromXml(xml, "SourceProcessId");
        var targetProcessGuid = ExtractStringFromXml(xml, "TargetProcessGUID");
        var targetProcessId = ExtractStringFromXml(xml, "TargetProcessId");
        var targetImage = ExtractStringFromXml(xml, "TargetImage");
        var grantedAccess = ExtractStringFromXml(xml, "GrantedAccess");
        var callTrace = ExtractStringFromXml(xml, "CallTrace");
        var target = FirstNonEmpty(targetImage, targetProcessId, sourceImage, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            sourceProcessGuid,
            ProcessEventCategory.Process,
            ProcessEventAction.ProcessAccess,
            target,
            $"Sysmon process access: {Path.GetFileName(sourceImage ?? process.ProcessName)} -> {Path.GetFileName(target)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"SourceImage: {sourceImage}",
                $"SourceProcessGUID: {sourceProcessGuid}",
                $"SourceProcessId: {sourceProcessId}",
                $"TargetImage: {targetImage}",
                $"TargetProcessGUID: {targetProcessGuid}",
                $"TargetProcessId: {targetProcessId}",
                $"GrantedAccess: {grantedAccess}",
                "",
                "CallTrace:",
                callTrace),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonProcessTamperingEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var type = ExtractStringFromXml(xml, "Type");
        var target = FirstNonEmpty(image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Process,
            ProcessEventAction.ProcessTampering,
            target,
            $"Sysmon process tampering: {FirstNonEmpty(type, Path.GetFileName(target))}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"Type: {type}",
                $"User: {process.UserName}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonNetworkEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var protocol = ExtractStringFromXml(xml, "Protocol");
        var sourceIp = ExtractStringFromXml(xml, "SourceIp");
        var sourcePort = ExtractStringFromXml(xml, "SourcePort");
        var destinationIp = ExtractStringFromXml(xml, "DestinationIp");
        var destinationPort = ExtractStringFromXml(xml, "DestinationPort");
        var destinationHostname = ExtractStringFromXml(xml, "DestinationHostname");
        var destination = FirstNonEmpty(destinationHostname, destinationIp);
        var target = string.IsNullOrWhiteSpace(destinationPort)
            ? destination
            : $"{destination}:{destinationPort}";
        var source = string.IsNullOrWhiteSpace(sourcePort)
            ? sourceIp
            : $"{sourceIp}:{sourcePort}";
        var displayProtocol = string.IsNullOrWhiteSpace(protocol) ? "Network" : protocol;

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Network,
            ProcessEventAction.Connect,
            target,
            $"Sysmon {displayProtocol} connect: {source} -> {target}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"Protocol: {protocol}",
                $"Source: {source}",
                $"Destination: {target}",
                $"Destination IP: {destinationIp}",
                $"Destination Hostname: {destinationHostname}",
                $"User: {process.UserName}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonFileDeleteEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var targetFilename = ExtractStringFromXml(xml, "TargetFilename");
        var hashes = ExtractStringFromXml(xml, "Hashes");
        var user = ExtractStringFromXml(xml, "User");
        var isExecutable = ExtractStringFromXml(xml, "IsExecutable");
        var target = FirstNonEmpty(targetFilename, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.File,
            ProcessEventAction.FileDelete,
            target,
            $"Sysmon file delete: {Path.GetFileName(target)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"TargetFilename: {targetFilename}",
                $"Hashes: {hashes}",
                $"IsExecutable: {isExecutable}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonFileCreateEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var targetFilename = ExtractStringFromXml(xml, "TargetFilename");
        var creationUtcTime = ExtractStringFromXml(xml, "CreationUtcTime");
        var user = ExtractStringFromXml(xml, "User");
        var target = FirstNonEmpty(targetFilename, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.File,
            ProcessEventAction.FileCreate,
            target,
            $"Sysmon file create: {Path.GetFileName(target)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"TargetFilename: {targetFilename}",
                $"CreationUtcTime: {creationUtcTime}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonFileCreateStreamHashEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var targetFilename = ExtractStringFromXml(xml, "TargetFilename");
        var creationUtcTime = ExtractStringFromXml(xml, "CreationUtcTime");
        var hash = ExtractStringFromXml(xml, "Hash");
        var contents = ExtractStringFromXml(xml, "Contents");
        var user = ExtractStringFromXml(xml, "User");
        var target = FirstNonEmpty(targetFilename, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.File,
            ProcessEventAction.FileCreateStreamHash,
            target,
            $"Sysmon file stream hash: {Path.GetFileName(target)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"TargetFilename: {targetFilename}",
                $"CreationUtcTime: {creationUtcTime}",
                $"Hash: {hash}",
                "",
                "Contents:",
                contents),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonPipeEvent(ProcessInfo process, EventRecord eventRecord, string xml, ProcessEventAction action)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var pipeName = ExtractStringFromXml(xml, "PipeName");
        var eventType = ExtractStringFromXml(xml, "EventType");
        var user = ExtractStringFromXml(xml, "User");
        var isCreate = action == ProcessEventAction.PipeCreated;
        var target = FirstNonEmpty(pipeName, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Process,
            action,
            target,
            isCreate
                ? $"Sysmon pipe created: {target}"
                : $"Sysmon pipe connected: {target}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"EventType: {eventType}",
                $"PipeName: {pipeName}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonWmiEvent(ProcessInfo process, EventRecord eventRecord, string xml, ProcessEventAction action)
    {
        var operation = action switch
        {
            ProcessEventAction.WmiFilter => "WMI filter",
            ProcessEventAction.WmiConsumer => "WMI consumer",
            ProcessEventAction.WmiBinding => "WMI binding",
            _ => "WMI event"
        };
        var name = ExtractStringFromXml(xml, "Name");
        var eventNamespace = ExtractStringFromXml(xml, "EventNamespace");
        var query = ExtractStringFromXml(xml, "Query");
        var destination = ExtractStringFromXml(xml, "Destination");
        var consumer = ExtractStringFromXml(xml, "Consumer");
        var filter = ExtractStringFromXml(xml, "Filter");
        var user = ExtractStringFromXml(xml, "User");
        var target = FirstNonEmpty(name, destination, consumer, filter, query, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            ExtractStringFromXml(xml, "ProcessGuid"),
            ProcessEventCategory.Wmi,
            action,
            target,
            $"Sysmon {operation}: {TrimSingleLine(target, 120)}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"Name: {name}",
                $"EventNamespace: {eventNamespace}",
                $"Query: {query}",
                $"Destination: {destination}",
                $"Consumer: {consumer}",
                $"Filter: {filter}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonDnsQueryEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var queryName = ExtractStringFromXml(xml, "QueryName");
        var queryStatus = ExtractStringFromXml(xml, "QueryStatus");
        var queryResults = ExtractStringFromXml(xml, "QueryResults");
        var user = ExtractStringFromXml(xml, "User");
        var target = FirstNonEmpty(queryName, image, process.ProcessPath, process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Dns,
            ProcessEventAction.DnsQuery,
            target,
            $"Sysmon DNS query: {target}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"QueryName: {queryName}",
                $"QueryStatus: {queryStatus}",
                $"QueryResults: {queryResults}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonRegistryCreateDeleteEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var eventType = ExtractStringFromXml(xml, "EventType");
        var targetObject = ExtractStringFromXml(xml, "TargetObject");
        var user = ExtractStringFromXml(xml, "User");
        var action = eventType?.Contains("Delete", StringComparison.OrdinalIgnoreCase) == true
            ? ProcessEventAction.RegistryDeleteKey
            : ProcessEventAction.RegistryCreateKey;
        var summaryPrefix = action == ProcessEventAction.RegistryDeleteKey ? "delete" : "create";

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Registry,
            action,
            targetObject ?? process.ProcessName,
            $"Sysmon registry {summaryPrefix}: {targetObject}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"EventType: {eventType}",
                $"TargetObject: {targetObject}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonRegistrySetValueEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var eventType = ExtractStringFromXml(xml, "EventType");
        var targetObject = ExtractStringFromXml(xml, "TargetObject");
        var details = ExtractStringFromXml(xml, "Details");
        var user = ExtractStringFromXml(xml, "User");

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Registry,
            ProcessEventAction.RegistrySetValue,
            targetObject ?? process.ProcessName,
            $"Sysmon registry set value: {targetObject}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"EventType: {eventType}",
                $"TargetObject: {targetObject}",
                $"Details: {details}"),
            "sysmon");
    }

    private ProcessEventInfo CreateSysmonRegistryRenameEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var image = ExtractStringFromXml(xml, "Image");
        var processGuid = ExtractStringFromXml(xml, "ProcessGuid");
        var eventType = ExtractStringFromXml(xml, "EventType");
        var targetObject = ExtractStringFromXml(xml, "TargetObject");
        var newName = ExtractStringFromXml(xml, "NewName");
        var user = ExtractStringFromXml(xml, "User");
        var action = targetObject?.Contains('\\') == true && targetObject.Contains("\\", StringComparison.Ordinal)
            ? ProcessEventAction.RegistryRenameValue
            : ProcessEventAction.RegistryRenameKey;

        return CreateSysmonEvent(
            process,
            eventRecord,
            processGuid,
            ProcessEventCategory.Registry,
            action,
            targetObject ?? process.ProcessName,
            $"Sysmon registry rename: {targetObject}",
            BuildEventRecordContent(
                eventRecord,
                xml,
                $"Image: {image}",
                $"ProcessGuid: {processGuid}",
                $"User: {FirstNonEmpty(user, process.UserName)}",
                $"EventType: {eventType}",
                $"TargetObject: {targetObject}",
                $"NewName: {newName}"),
            "sysmon");
    }

    private static ProcessEventInfo CreateNetworkEvent(
        ProcessInfo process,
        TcpConnectionSnapshot connection,
        ProcessEventAction action,
        DateTime timestampUtc)
    {
        var isConnect = action == ProcessEventAction.Connect;
        var target = $"{connection.RemoteAddress}:{connection.RemotePort}";
        var local = $"{connection.LocalAddress}:{connection.LocalPort}";

        return new ProcessEventInfo
        {
            TimestampUtc = timestampUtc,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            Category = ProcessEventCategory.Network,
            Action = action,
            Target = target,
            Summary = isConnect
                ? $"TCP connect: {local} -> {target}"
                : $"TCP disconnect: {local} -> {target}",
            Details = $"State: {connection.State}; User: {process.UserName}; Command line: {process.CommandLine}",
            IsInteresting = true
        };
    }

    private static ProcessEventInfo CreateSysmonEvent(
        ProcessInfo process,
        EventRecord eventRecord,
        string? processGuid,
        ProcessEventCategory category,
        ProcessEventAction action,
        string target,
        string summary,
        string details,
        string riskFlags)
    {
        return new ProcessEventInfo
        {
            TimestampUtc = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessGuid = processGuid ?? string.Empty,
            ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
            ProcessName = process.ProcessName,
            ParentProcessId = process.ParentProcessId,
            EventCode = eventRecord.Id,
            Category = category,
            Action = action,
            Target = target,
            Summary = summary,
            Details = details,
            RiskFlags = riskFlags,
            IsInteresting = true
        };
    }

    private void AddTargetProcessEventIfAvailable(List<ProcessEventInfo> events, ProcessEventInfo primaryEvent, EventRecord eventRecord, string xml)
    {
        if (eventRecord.Id is not (8 or 10))
        {
            return;
        }

        var targetProcessGuid = ExtractStringFromXml(xml, "TargetProcessGUID");
        var targetProcessId = ExtractIntFromXml(xml, "TargetProcessId");
        var targetImage = ExtractStringFromXml(xml, "TargetImage");
        var eventTimeUtc = ExtractSysmonUtcTime(xml) ?? eventRecord.TimeCreated?.ToUniversalTime();
        var targetProcess = ResolveSysmonTrackedProcess(targetProcessGuid, targetProcessId, targetImage, eventTimeUtc, targetImage, null);
        if (targetProcess == null || targetProcess.GetUniqueKey() == primaryEvent.ProcessKey)
        {
            return;
        }

        events.Add(CreateSysmonEvent(
            targetProcess,
            eventRecord,
            targetProcessGuid,
            primaryEvent.Category,
            primaryEvent.Action,
            primaryEvent.Target,
            $"{primaryEvent.Summary} (target process)",
            BuildMultilineDetails(
                "Displayed for target process correlation.",
                primaryEvent.Details),
            primaryEvent.RiskFlags));
    }

    private ProcessEventInfo CreateGenericSysmonEvent(ProcessInfo process, EventRecord eventRecord, string xml)
    {
        var eventName = ExtractStringFromXml(xml, "EventType");
        var target = FirstNonEmpty(
            ExtractStringFromXml(xml, "TargetFilename"),
            ExtractStringFromXml(xml, "TargetObject"),
            ExtractStringFromXml(xml, "PipeName"),
            ExtractStringFromXml(xml, "Image"),
            process.ProcessPath,
            process.ProcessName);

        return CreateSysmonEvent(
            process,
            eventRecord,
            ExtractStringFromXml(xml, "ProcessGuid") ?? ExtractStringFromXml(xml, "SourceProcessGUID"),
            ProcessEventCategory.Process,
            ProcessEventAction.GenericSysmon,
            target,
            $"Sysmon event {eventRecord.Id}: {FirstNonEmpty(eventName, target)}",
            BuildEventRecordContent(eventRecord, xml, $"Event ID: {eventRecord.Id}", $"Target: {target}"),
            "sysmon");
    }

    private static ProcessEventInfo CreateGenericSysmonEventForProvider(EventRecord eventRecord, string xml)
    {
        var timestampUtc = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
        var target = FirstNonEmpty(
            ExtractStringFromXml(xml, "Image"),
            ExtractStringFromXml(xml, "TargetFilename"),
            ExtractStringFromXml(xml, "TargetObject"),
            ExtractStringFromXml(xml, "PipeName"),
            eventRecord.ProviderName,
            "Sysmon");

        return new ProcessEventInfo
        {
            TimestampUtc = timestampUtc,
            ProcessKey = $"sysmon_provider_{eventRecord.Id}_{timestampUtc.Ticks}",
            ProcessId = eventRecord.ProcessId ?? 0,
            ProcessGuid = ExtractStringFromXml(xml, "ProcessGuid") ?? ExtractStringFromXml(xml, "SourceProcessGUID") ?? string.Empty,
            ProcessName = eventRecord.ProviderName ?? "Sysmon",
            EventCode = eventRecord.Id,
            Category = ProcessEventCategory.Process,
            Action = ProcessEventAction.GenericSysmon,
            Target = target,
            Summary = $"Sysmon event {eventRecord.Id}: {target}",
            Details = BuildEventRecordContent(eventRecord, xml, $"Event ID: {eventRecord.Id}", $"Target: {target}"),
            RiskFlags = "sysmon",
            IsInteresting = true
        };
    }

    private static string? ExtractStringFromXml(string xml, string dataName)
    {
        var marker = $"Name='{dataName}'>";
        var start = xml.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            marker = $"Name=\"{dataName}\">";
            start = xml.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return null;
            }
        }

        start += marker.Length;
        var end = xml.IndexOf("</Data>", start, StringComparison.OrdinalIgnoreCase);
        if (end < 0)
        {
            return null;
        }

        return xml[start..end].Trim();
    }

    private static bool IsCandidateSysmonRecordForProcess(EventRecord eventRecord, ProcessInfo process)
    {
        var xml = eventRecord.ToXml();
        var processId = ExtractIntFromXml(xml, "ProcessId");
        var sourceProcessId = ExtractIntFromXml(xml, "SourceProcessId");
        var targetProcessId = ExtractIntFromXml(xml, "TargetProcessId");

        if (processId != process.ProcessId &&
            sourceProcessId != process.ProcessId &&
            targetProcessId != process.ProcessId)
        {
            return false;
        }

        var image = FirstNonEmpty(
            ExtractStringFromXml(xml, "Image"),
            ExtractStringFromXml(xml, "SourceImage"),
            ExtractStringFromXml(xml, "TargetImage"));

        if (string.IsNullOrWhiteSpace(image) ||
            string.IsNullOrWhiteSpace(process.ProcessPath) ||
            string.Equals(process.ProcessPath, "<not available>", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(process.ProcessPath, "<access denied>", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return string.Equals(image, process.ProcessPath, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCandidateWindowsRecordForProcess(EventRecord eventRecord, ProcessInfo process)
    {
        var xml = eventRecord.ToXml();
        var includeExecutionProcessId = !string.Equals(GetEventLogName(eventRecord), SecurityLogName, StringComparison.OrdinalIgnoreCase);
        var processIds = ExtractWindowsProcessIds(xml, includeExecutionProcessId);

        if (includeExecutionProcessId && eventRecord.ProcessId.HasValue)
        {
            processIds.Add(eventRecord.ProcessId.Value);
        }

        if (processIds.Contains(process.ProcessId))
        {
            return true;
        }

        var eventTimeUtc = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
        return IsWindowsRecordPathMatch(xml, process) &&
               IsProcessAliveNear(process, eventTimeUtc, TimeSpan.FromSeconds(30));
    }

    private ProcessInfo? ResolveWindowsEventProcess(EventRecord eventRecord, string xml, DateTime timestampUtc)
    {
        var includeExecutionProcessId = !string.Equals(GetEventLogName(eventRecord), SecurityLogName, StringComparison.OrdinalIgnoreCase);
        foreach (var processId in ExtractWindowsProcessIds(xml, includeExecutionProcessId))
        {
            var process = _processTracker.GetBestProcessMatch(
                processId,
                ExtractWindowsRecordProcessName(xml),
                timestampUtc);
            if (process != null)
            {
                return process;
            }
        }

        if (includeExecutionProcessId && eventRecord.ProcessId.HasValue && eventRecord.ProcessId.Value > 0)
        {
            var process = _processTracker.GetBestProcessMatch(
                eventRecord.ProcessId.Value,
                ExtractWindowsRecordProcessName(xml),
                timestampUtc);
            if (process != null)
            {
                return process;
            }
        }

        return _processTracker.GetAllProcesses()
            .Where(process => IsWindowsRecordPathMatch(xml, process))
            .Where(process => IsProcessAliveNear(process, timestampUtc, TimeSpan.FromSeconds(30)))
            .OrderByDescending(process => process.Status == ProcessStatus.Running ? 1 : 0)
            .ThenByDescending(process => process.StartTime ?? process.EndTime ?? DateTime.MinValue)
            .FirstOrDefault();
    }

    private static bool IsWindowsRecordPathMatch(string xml, ProcessInfo process)
    {
        var candidateValues = ExtractWindowsRecordPathCandidates(xml);
        if (candidateValues.Count == 0)
        {
            return false;
        }

        foreach (var candidate in candidateValues)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            if (string.Equals(process.ProcessPath, candidate, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(process.ProcessName, candidate, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(process.ProcessName, Path.GetFileName(candidate), StringComparison.OrdinalIgnoreCase) ||
                string.Equals(process.ProcessName, Path.GetFileNameWithoutExtension(candidate), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static List<string> ExtractWindowsRecordPathCandidates(string xml)
    {
        var fieldNames = new[]
        {
            "ProcessName",
            "ProcessPath",
            "Application",
            "ApplicationPath",
            "Image",
            "ImagePath",
            "Path",
            "FilePath",
            "FileName",
            "NewProcessName",
            "ServiceFileName",
            "param1",
            "param2",
            "CommandLine"
        };

        return fieldNames
            .Select(fieldName => ExtractStringFromXml(xml, fieldName))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .SelectMany(SplitPossibleCommandLine)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? ExtractWindowsRecordProcessName(string xml)
    {
        return FirstNonEmpty(
            ExtractStringFromXml(xml, "ProcessName"),
            ExtractStringFromXml(xml, "ProcessPath"),
            ExtractStringFromXml(xml, "Application"),
            ExtractStringFromXml(xml, "ApplicationPath"),
            ExtractStringFromXml(xml, "Image"),
            ExtractStringFromXml(xml, "ImagePath"),
            ExtractStringFromXml(xml, "FileName"),
            ExtractStringFromXml(xml, "NewProcessName"));
    }

    private static IEnumerable<string> SplitPossibleCommandLine(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            yield break;
        }

        var trimmed = value.Trim();
        yield return trimmed;

        if (trimmed.StartsWith("\"", StringComparison.Ordinal))
        {
            var closingQuote = trimmed.IndexOf('"', 1);
            if (closingQuote > 1)
            {
                yield return trimmed[1..closingQuote];
            }

            yield break;
        }

        var firstSpace = trimmed.IndexOf(' ');
        if (firstSpace > 0)
        {
            yield return trimmed[..firstSpace];
        }
    }

    private static bool IsProcessAliveNear(ProcessInfo process, DateTime timestampUtc, TimeSpan tolerance)
    {
        var timestampLocal = timestampUtc.ToLocalTime();
        var startsBefore = !process.StartTime.HasValue || process.StartTime.Value <= timestampLocal.Add(tolerance);
        var endsAfter = !process.EndTime.HasValue || process.EndTime.Value >= timestampLocal.Subtract(tolerance);
        return startsBefore && endsAfter;
    }

    private static int ExtractWindowsProcessId(string xml, bool includeExecutionProcessId)
    {
        return ExtractWindowsProcessIds(xml, includeExecutionProcessId).FirstOrDefault();
    }

    private static HashSet<int> ExtractWindowsProcessIds(string xml, bool includeExecutionProcessId)
    {
        var processIds = new HashSet<int>();
        var fieldNames = new[]
        {
            "NewProcessId",
            "ProcessId",
            "ClientProcessId",
            "CallerProcessId",
            "SubjectProcessId",
            "TargetProcessId"
        };

        foreach (var fieldName in fieldNames)
        {
            AddProcessIdIfValid(processIds, ExtractStringFromXml(xml, fieldName));
        }

        if (includeExecutionProcessId)
        {
            AddProcessIdIfValid(processIds, ExtractExecutionProcessId(xml).ToString(CultureInfo.InvariantCulture));
        }

        processIds.Remove(0);
        return processIds;
    }

    private static void AddProcessIdIfValid(HashSet<int> processIds, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return;
        }

        var value = rawValue.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsedHex))
            {
                processIds.Add(parsedHex);
            }

            return;
        }

        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedDecimal))
        {
            processIds.Add(parsedDecimal);
        }
    }

    private static string GetSysmonRecordKey(EventRecord eventRecord)
    {
        return GetEventRecordKey(eventRecord);
    }

    private static string GetEventRecordKey(EventRecord eventRecord)
    {
        return eventRecord.RecordId.HasValue
            ? $"{GetEventLogName(eventRecord)}:{eventRecord.RecordId.Value}"
            : string.Empty;
    }

    private static string GetEventLogName(EventRecord eventRecord)
    {
        return eventRecord.LogName ?? eventRecord.ProviderName ?? "Windows";
    }

    private bool TryMarkRecordImported(BoundedRecordKeySet importedRecords, string recordKey)
    {
        return importedRecords.Add(recordKey);
    }

    private void UnmarkRecordImported(BoundedRecordKeySet importedRecords, string recordKey)
    {
        importedRecords.Remove(recordKey);
    }

    private bool TryMarkSysmonRecordImported(string recordKey)
    {
        return _importedSysmonRecords.Add(recordKey);
    }

    private void UnmarkSysmonRecordImported(string recordKey)
    {
        _importedSysmonRecords.Remove(recordKey);
    }

    private static int ExtractIntFromXml(string xml, string dataName)
    {
        var value = ExtractStringFromXml(xml, dataName);
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(normalized[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsedHex)
                ? parsedHex
                : 0;
        }

        return int.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;
    }

    private static DateTime? ExtractSysmonUtcTime(string xml)
    {
        var rawUtcTime = ExtractStringFromXml(xml, "UtcTime");
        if (string.IsNullOrWhiteSpace(rawUtcTime))
        {
            return null;
        }

        if (DateTime.TryParse(
                rawUtcTime,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var utcTime))
        {
            return utcTime;
        }

        return null;
    }

    private static string? ExtractHashValue(string? hashes, string hashName)
    {
        if (string.IsNullOrWhiteSpace(hashes))
        {
            return null;
        }

        var prefix = hashName + "=";
        foreach (var part in hashes.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[prefix.Length..];
            }
        }

        return null;
    }

    private static int ExtractExecutionProcessId(string xml)
    {
        var marker = "Execution ProcessID='";
        var start = xml.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            marker = "Execution ProcessID=\"";
            start = xml.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return 0;
            }
        }

        start += marker.Length;
        var end = xml.IndexOfAny(new[] { '\'', '"' }, start);
        if (end < 0)
        {
            return 0;
        }

        return int.TryParse(xml[start..end], out var processId) ? processId : 0;
    }

    private static string? ExtractUnnamedDataValue(string xml, int index)
    {
        var searchStart = 0;
        for (var i = 0; i <= index; i++)
        {
            var start = xml.IndexOf("<Data>", searchStart, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return null;
            }

            start += "<Data>".Length;
            var end = xml.IndexOf("</Data>", start, StringComparison.OrdinalIgnoreCase);
            if (end < 0)
            {
                return null;
            }

            if (i == index)
            {
                return xml[start..end].Trim();
            }

            searchStart = end + "</Data>".Length;
        }

        return null;
    }

    private static string? ExtractContextValue(string? context, string key)
    {
        if (string.IsNullOrWhiteSpace(context))
        {
            return null;
        }

        foreach (var line in context.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith(key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var separatorIndex = trimmed.IndexOf('=');
            if (separatorIndex >= 0)
            {
                return trimmed[(separatorIndex + 1)..].Trim();
            }

            separatorIndex = trimmed.IndexOf(':');
            if (separatorIndex >= 0)
            {
                return trimmed[(separatorIndex + 1)..].Trim();
            }
        }

        return null;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private sealed class BoundedRecordKeySet
    {
        private readonly int _capacity;
        private readonly Dictionary<string, long> _keys = new(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<(string Key, long Generation)> _order = new();
        private readonly object _lock = new();
        private long _nextGeneration;
        private long _evictedCount;

        public BoundedRecordKeySet(int capacity)
        {
            _capacity = Math.Max(1, capacity);
        }

        public bool Add(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return false;
            }

            lock (_lock)
            {
                if (_keys.ContainsKey(key))
                {
                    return false;
                }

                var generation = ++_nextGeneration;
                _keys[key] = generation;
                _order.Enqueue((key, generation));
                Trim();
                CompactIfNeeded();
                return true;
            }
        }

        public void Remove(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return;
            }

            lock (_lock)
            {
                _keys.Remove(key);
            }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _keys.Clear();
                _order.Clear();
                _evictedCount = 0;
            }
        }

        public RecordKeySetSnapshot GetSnapshot()
        {
            lock (_lock)
            {
                return new RecordKeySetSnapshot(_keys.Count, _capacity, _evictedCount);
            }
        }

        private void Trim()
        {
            while (_keys.Count > _capacity && _order.Count > 0)
            {
                var stale = _order.Dequeue();
                if (_keys.TryGetValue(stale.Key, out var generation) && generation == stale.Generation)
                {
                    _keys.Remove(stale.Key);
                    _evictedCount++;
                }
            }
        }

        private void CompactIfNeeded()
        {
            if (_order.Count <= _capacity * 2)
            {
                return;
            }

            _order.Clear();
            foreach (var entry in _keys)
            {
                _order.Enqueue((entry.Key, entry.Value));
            }
        }
    }

    private sealed class EventSourceIngressCounters
    {
        public long RecordsSeen;
        public long RecordsMatched;
        public long DuplicateRecords;
        public long UnmatchedRecords;
        public long MalformedRecords;
    }

    private readonly record struct RecordKeySetSnapshot(int Count, int Capacity, long Evicted);

    private readonly record struct EventSourceIngressSnapshot(
        long RecordsSeen,
        long RecordsMatched,
        long DuplicateRecords,
        long UnmatchedRecords,
        long MalformedRecords);

    private static string NormalizeWhitespace(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : string.Join(" ", value.Split(new[] { '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)).Trim();
    }

    private static string TrimSingleLine(string value, int maxLength)
    {
        var normalized = NormalizeWhitespace(value);
        if (normalized.Length <= maxLength)
        {
            return normalized;
        }

        return normalized[..(maxLength - 3)] + "...";
    }

    private ProcessInfo? ResolveTrackedProcess(int processId)
    {
        return _processTracker.GetRunningProcessById(processId)
            ?? _processTracker.GetLatestProcessById(processId);
    }

    private void TrackSysmonProcess(string? processGuid, ProcessInfo process)
    {
        if (string.IsNullOrWhiteSpace(processGuid))
        {
            return;
        }

        lock (_sysmonLock)
        {
            _sysmonProcessMap[processGuid] = process.GetUniqueKey();
        }
    }

    private ProcessInfo? ResolveSysmonTrackedProcess(
        string? processGuid,
        int processId,
        string? processName,
        DateTime? eventTimeUtc,
        string? processPath,
        string? commandLine)
    {
        if (!string.IsNullOrWhiteSpace(processGuid))
        {
            lock (_sysmonLock)
            {
                if (_sysmonProcessMap.TryGetValue(processGuid, out var processKey))
                {
                    var trackedProcess = _processTracker.GetProcess(processKey);
                    if (trackedProcess != null)
                    {
                        return trackedProcess;
                    }
                }
            }
        }

        return _processTracker.CorrelateSysmonProcess(
            processGuid,
            processId,
            processName,
            eventTimeUtc,
            processPath,
            commandLine);
    }

    private void TrackPowerShellActivity(int processId, DateTime timestampUtc)
    {
        lock (_powerShellLock)
        {
            _recentPowerShellActivity[processId] = timestampUtc;

            var cutoff = timestampUtc.AddMinutes(-5);
            foreach (var staleProcessId in _recentPowerShellActivity
                         .Where(kvp => kvp.Value < cutoff)
                         .Select(kvp => kvp.Key)
                         .ToList())
            {
                _recentPowerShellActivity.Remove(staleProcessId);
            }
        }
    }

    private ProcessInfo? ResolveTranscriptProcess(DateTime timestampUtc)
    {
        List<int> candidateProcessIds;
        lock (_powerShellLock)
        {
            candidateProcessIds = _recentPowerShellActivity
                .Where(kvp => Math.Abs((kvp.Value - timestampUtc).TotalSeconds) <= 30)
                .OrderByDescending(kvp => kvp.Value)
                .Select(kvp => kvp.Key)
                .ToList();
        }

        foreach (var processId in candidateProcessIds)
        {
            var trackedProcess = ResolveTrackedProcess(processId);
            if (trackedProcess != null && IsPowerShellProcess(trackedProcess))
            {
                return trackedProcess;
            }
        }

        return _processTracker.GetAllProcesses()
            .Where(IsPowerShellProcess)
            .Select(process => new
            {
                Process = process,
                StartTimeUtc = process.StartTime?.ToUniversalTime()
            })
            .Where(entry => entry.StartTimeUtc.HasValue)
            .Where(entry => Math.Abs((entry.StartTimeUtc!.Value - timestampUtc).TotalMinutes) <= 2)
            .Select(entry => entry.Process)
            .OrderByDescending(process => process.StartTime)
            .FirstOrDefault();
    }

    private static bool IsPowerShellProcess(ProcessInfo process)
    {
        return process.ProcessName.Contains("powershell", StringComparison.OrdinalIgnoreCase)
            || process.ProcessName.Contains("pwsh", StringComparison.OrdinalIgnoreCase);
    }

    private static int ConvertPort(uint port)
    {
        var bytes = BitConverter.GetBytes(port);
        return (bytes[0] << 8) + bytes[1];
    }

    private static string BuildAuditEventDetails(EventRecord eventRecord, string xml, params string?[] lines)
    {
        var renderedMessage = SafeFormatDescription(eventRecord);
        var detailLines = new List<string>();

        foreach (var line in lines)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                detailLines.Add(line);
            }
        }

        if (!string.IsNullOrWhiteSpace(renderedMessage))
        {
            detailLines.Add(string.Empty);
            detailLines.Add("Rendered Message:");
            detailLines.Add(renderedMessage);
        }

        detailLines.Add(string.Empty);
        detailLines.Add("Event XML:");
        detailLines.Add(xml);

        return string.Join(Environment.NewLine, detailLines);
    }

    private static string BuildEventRecordContent(EventRecord eventRecord, string xml, params string?[] lines)
    {
        return BuildAuditEventDetails(eventRecord, xml, lines);
    }

    private static string BuildMultilineDetails(params string?[] lines)
    {
        return string.Join(Environment.NewLine, lines.Where(line => !string.IsNullOrWhiteSpace(line)));
    }

    private static string SafeFormatDescription(EventRecord eventRecord)
    {
        try
        {
            return eventRecord.FormatDescription() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved);

    private const int AddressFamilyInet = 2;
    private const int TcpTableOwnerPidAll = 5;

    private sealed class TcpConnectionSnapshot
    {
        public TcpConnectionSnapshot(int processId, string localAddress, int localPort, string remoteAddress, int remotePort, TcpState state)
        {
            ProcessId = processId;
            LocalAddress = localAddress;
            LocalPort = localPort;
            RemoteAddress = remoteAddress;
            RemotePort = remotePort;
            State = state;
            Key = $"{processId}|{localAddress}|{localPort}|{remoteAddress}|{remotePort}";
        }

        public int ProcessId { get; }
        public string LocalAddress { get; }
        public int LocalPort { get; }
        public string RemoteAddress { get; }
        public int RemotePort { get; }
        public TcpState State { get; }
        public string Key { get; }
    }
}

public sealed record EventSourceHealthSnapshot(
    string Source,
    string Status,
    string Detail,
    bool IsEnabled,
    bool IsActive,
    DateTime UpdatedUtc,
    string Error,
    int DedupKeyCount = 0,
    int DedupKeyCapacity = 0,
    long DedupKeysEvicted = 0,
    long RecordsSeen = 0,
    long RecordsMatched = 0,
    long DuplicateRecords = 0,
    long UnmatchedRecords = 0,
    long MalformedRecords = 0);
