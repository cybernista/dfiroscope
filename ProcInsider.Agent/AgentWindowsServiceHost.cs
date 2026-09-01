using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.Services.Infrastructure;

namespace ProcInsider.Agent;

internal delegate Task<int> AgentServiceRuntime(
    AgentOptions options,
    Action runtimeReady,
    CancellationToken cancellationToken);

internal enum AgentServiceLifecycleState
{
    StartPending = 0,
    Running = 1,
    StopPending = 2,
    Stopped = 3,
    Failed = 4
}

internal sealed record AgentServiceLifecycleSnapshot(
    AgentServiceLifecycleState State,
    DateTime EmittedAtUtc,
    string ServiceName,
    int ProcessId,
    string ErrorCode,
    string Message,
    int RuntimeExitCode = 0);

internal sealed record AgentServiceLifecycleOutcome(
    bool Succeeded,
    string ErrorCode,
    string Message,
    int RuntimeExitCode);

/// <summary>
/// Owns only the SCM/process-lifetime boundary. The supplied runtime is the same
/// AgentProcessRunner used by Interactive startup.
/// </summary>
internal sealed class AgentServiceRuntimeCoordinator
{
    private readonly string _serviceName;
    private readonly AgentOptions _options;
    private readonly AgentServiceRuntime _runtime;
    private readonly Action<AgentServiceLifecycleSnapshot> _report;
    private readonly TimeSpan _startTimeout;
    private readonly TimeSpan _stopTimeout;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _stopRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _stopRequestPublished;

    public AgentServiceRuntimeCoordinator(
        string serviceName,
        AgentOptions options,
        AgentServiceRuntime runtime,
        Action<AgentServiceLifecycleSnapshot> report,
        TimeSpan startTimeout,
        TimeSpan stopTimeout)
    {
        _serviceName = serviceName;
        _options = options;
        _runtime = runtime;
        _report = report;
        _startTimeout = startTimeout;
        _stopTimeout = stopTimeout;
    }

    public void RequestStop()
    {
        if (Interlocked.Exchange(ref _stopRequestPublished, 1) != 0)
        {
            return;
        }

        Publish(AgentServiceLifecycleState.StopPending, string.Empty, "SCM stop requested.");
        _shutdown.Cancel();
        _stopRequested.TrySetResult();
    }

    public async Task<AgentServiceLifecycleOutcome> RunAsync()
    {
        Publish(AgentServiceLifecycleState.StartPending, string.Empty, "Agent Service runtime is starting.");
        var runtimeTask = Task.Run(
            () => _runtime(_options, () => _ready.TrySetResult(), _shutdown.Token));
        var startTimeoutTask = Task.Delay(_startTimeout);
        var startCompletion = await Task.WhenAny(
                _ready.Task,
                runtimeTask,
                _stopRequested.Task,
                startTimeoutTask)
            .ConfigureAwait(false);

        if (startCompletion == startTimeoutTask)
        {
            _shutdown.Cancel();
            return await FailAfterBoundedStopAsync(
                    runtimeTask,
                    "ServiceStartTimeout",
                    $"The shared Agent runtime did not become ready within {_startTimeout.TotalSeconds:N0} seconds.")
                .ConfigureAwait(false);
        }

        if (startCompletion == runtimeTask)
        {
            return await CompleteRuntimeAsync(runtimeTask, "ServiceStartFailed").ConfigureAwait(false);
        }

        if (startCompletion == _stopRequested.Task)
        {
            return await CompleteAfterStopAsync(runtimeTask).ConfigureAwait(false);
        }

        Publish(AgentServiceLifecycleState.Running, string.Empty, "Shared Agent runtime is ready.");
        var completion = await Task.WhenAny(runtimeTask, _stopRequested.Task).ConfigureAwait(false);
        return completion == runtimeTask
            ? await CompleteRuntimeAsync(runtimeTask, "ServiceRuntimeFailed").ConfigureAwait(false)
            : await CompleteAfterStopAsync(runtimeTask).ConfigureAwait(false);
    }

    private async Task<AgentServiceLifecycleOutcome> CompleteAfterStopAsync(Task<int> runtimeTask)
    {
        var completed = await Task.WhenAny(runtimeTask, Task.Delay(_stopTimeout)).ConfigureAwait(false);
        if (completed != runtimeTask)
        {
            return Fail(
                "ServiceStopTimeout",
                $"The shared Agent runtime did not drain and stop within {_stopTimeout.TotalSeconds:N0} seconds.",
                runtimeExitCode: 2);
        }

        return await CompleteRuntimeAsync(runtimeTask, "ServiceStopFailed").ConfigureAwait(false);
    }

    private async Task<AgentServiceLifecycleOutcome> FailAfterBoundedStopAsync(
        Task<int> runtimeTask,
        string errorCode,
        string message)
    {
        await Task.WhenAny(runtimeTask, Task.Delay(_stopTimeout)).ConfigureAwait(false);
        return Fail(errorCode, message, runtimeExitCode: 2);
    }

    private async Task<AgentServiceLifecycleOutcome> CompleteRuntimeAsync(
        Task<int> runtimeTask,
        string failureCode)
    {
        try
        {
            var exitCode = await runtimeTask.ConfigureAwait(false);
            if (exitCode != 0)
            {
                return Fail(
                    failureCode,
                    $"The shared Agent runtime exited with code {exitCode}.",
                    exitCode);
            }

            Publish(AgentServiceLifecycleState.Stopped, string.Empty, "Shared Agent runtime stopped cleanly.");
            return new AgentServiceLifecycleOutcome(true, string.Empty, "Stopped cleanly.", 0);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
            Publish(AgentServiceLifecycleState.Stopped, string.Empty, "Shared Agent runtime accepted cancellation and stopped cleanly.");
            return new AgentServiceLifecycleOutcome(true, string.Empty, "Stopped cleanly.", 0);
        }
        catch (Exception ex)
        {
            return Fail(failureCode, ex.Message, runtimeExitCode: 1);
        }
    }

    private AgentServiceLifecycleOutcome Fail(string errorCode, string message, int runtimeExitCode)
    {
        Publish(AgentServiceLifecycleState.Failed, errorCode, message, runtimeExitCode);
        return new AgentServiceLifecycleOutcome(false, errorCode, message, runtimeExitCode);
    }

    private void Publish(
        AgentServiceLifecycleState state,
        string errorCode,
        string message,
        int runtimeExitCode = 0) =>
        _report(new AgentServiceLifecycleSnapshot(
            state,
            DateTime.UtcNow,
            _serviceName,
            Environment.ProcessId,
            errorCode,
            message,
            runtimeExitCode));
}

internal static class AgentWindowsServiceHost
{
    public const string ServiceName = "DFIRoscope.Agent";
    internal static readonly TimeSpan DefaultStartTimeout = TimeSpan.FromSeconds(60);
    internal static readonly TimeSpan DefaultStopTimeout = TimeSpan.FromSeconds(45);

    public static int Run(
        InfrastructureModeAccessService access,
        AgentOptions options,
        AgentServiceRuntime runtime,
        Action<AgentServiceLifecycleSnapshot>? report = null,
        string serviceName = ServiceName,
        TimeSpan? startTimeout = null,
        TimeSpan? stopTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(runtime);

        if (!access.TryCreate(
                InfrastructureEntryPointKind.ServiceConstruction,
                () => new NativeServiceHost(
                    serviceName,
                    options,
                    runtime,
                    report ?? CreateMachineReporter(),
                    startTimeout ?? DefaultStartTimeout,
                    stopTimeout ?? DefaultStopTimeout),
                out var host,
                out var decision))
        {
            Console.Error.WriteLine($"{decision.ErrorCode}: {decision.Message}");
            return 5;
        }

        var machinePaths = SessionPathService.GetInfrastructureAgentMachinePaths();
        if (!InfrastructureConfigurationStoreAccess.TryCreateAgentStore(
                access,
                machinePaths,
                out var configurationStore,
                out var configurationDecision))
        {
            Console.Error.WriteLine($"{configurationDecision.ErrorCode}: {configurationDecision.Message}");
            return 5;
        }

        host!.SetOptions(options with
        {
            InfrastructureConfigurationStore = configurationStore,
            InfrastructureAccess = access
        });
        return host.RunDispatcher();
    }

    private static Action<AgentServiceLifecycleSnapshot> CreateMachineReporter()
    {
        var path = SessionPathService.GetInfrastructureAgentMachinePaths().ServiceLifecycleLogPath;
        return snapshot =>
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, JsonSerializer.Serialize(snapshot) + Environment.NewLine);
        };
    }

    private sealed class NativeServiceHost
    {
        private const int ErrorFailedServiceControllerConnect = 1063;
        private const uint ErrorServiceSpecificError = 1066;
        private const uint ServiceWin32OwnProcess = 0x00000010;
        private const uint ServiceStopped = 0x00000001;
        private const uint ServiceStartPending = 0x00000002;
        private const uint ServiceStopPending = 0x00000003;
        private const uint ServiceRunning = 0x00000004;
        private const uint ServiceAcceptStop = 0x00000001;
        private const uint ServiceAcceptShutdown = 0x00000004;
        private const uint ServiceControlStop = 0x00000001;
        private const uint ServiceControlInterrogate = 0x00000004;
        private const uint ServiceControlShutdown = 0x00000005;
        private const uint NoError = 0;

        private readonly string _serviceName;
        private AgentOptions _options;
        private readonly AgentServiceRuntime _runtime;
        private readonly Action<AgentServiceLifecycleSnapshot> _report;
        private readonly TimeSpan _startTimeout;
        private readonly TimeSpan _stopTimeout;
        private readonly ServiceMainFunction _serviceMain;
        private readonly HandlerFunction _handler;
        private AgentServiceRuntimeCoordinator? _coordinator;
        private nint _statusHandle;
        private ServiceStatus _status;
        private int _checkpoint;

        public NativeServiceHost(
            string serviceName,
            AgentOptions options,
            AgentServiceRuntime runtime,
            Action<AgentServiceLifecycleSnapshot> report,
            TimeSpan startTimeout,
            TimeSpan stopTimeout)
        {
            _serviceName = serviceName;
            _options = options;
            _runtime = runtime;
            _report = report;
            _startTimeout = startTimeout;
            _stopTimeout = stopTimeout;
            _serviceMain = ServiceMain;
            _handler = HandleControl;
        }

        public void SetOptions(AgentOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options;
        }

        public int RunDispatcher()
        {
            var table = new[]
            {
                new ServiceTableEntry { ServiceName = _serviceName, ServiceMain = _serviceMain },
                new ServiceTableEntry()
            };
            if (StartServiceCtrlDispatcher(table))
            {
                return 0;
            }

            var error = Marshal.GetLastWin32Error();
            _report(new AgentServiceLifecycleSnapshot(
                AgentServiceLifecycleState.Failed,
                DateTime.UtcNow,
                _serviceName,
                Environment.ProcessId,
                error == ErrorFailedServiceControllerConnect
                    ? "NotStartedByServiceControlManager"
                    : "ServiceDispatcherFailed",
                new Win32Exception(error).Message,
                error));
            return error == 0 ? 1 : error;
        }

        private void ServiceMain(int argumentCount, nint arguments)
        {
            _statusHandle = RegisterServiceCtrlHandlerEx(_serviceName, _handler, 0);
            if (_statusHandle == 0)
            {
                return;
            }

            _coordinator = new AgentServiceRuntimeCoordinator(
                _serviceName,
                _options,
                _runtime,
                snapshot =>
                {
                    _report(snapshot);
                    ProjectStatus(snapshot);
                },
                _startTimeout,
                _stopTimeout);
            var outcome = _coordinator.RunAsync().GetAwaiter().GetResult();
            if (outcome.Succeeded)
            {
                SetStatus(ServiceStopped, controlsAccepted: 0, win32ExitCode: NoError, serviceSpecificExitCode: 0, waitHint: 0);
            }
            else
            {
                SetStatus(
                    ServiceStopped,
                    controlsAccepted: 0,
                    win32ExitCode: ErrorServiceSpecificError,
                    serviceSpecificExitCode: (uint)Math.Max(1, outcome.RuntimeExitCode),
                    waitHint: 0);
            }
        }

        private uint HandleControl(uint control, uint eventType, nint eventData, nint context)
        {
            switch (control)
            {
                case ServiceControlStop:
                case ServiceControlShutdown:
                    _coordinator?.RequestStop();
                    return NoError;
                case ServiceControlInterrogate:
                    SetServiceStatus(_statusHandle, ref _status);
                    return NoError;
                default:
                    return NoError;
            }
        }

        private void ProjectStatus(AgentServiceLifecycleSnapshot snapshot)
        {
            switch (snapshot.State)
            {
                case AgentServiceLifecycleState.StartPending:
                    SetStatus(ServiceStartPending, 0, NoError, 0, (uint)_startTimeout.TotalMilliseconds);
                    break;
                case AgentServiceLifecycleState.Running:
                    SetStatus(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, NoError, 0, 0);
                    break;
                case AgentServiceLifecycleState.StopPending:
                    SetStatus(ServiceStopPending, 0, NoError, 0, (uint)_stopTimeout.TotalMilliseconds);
                    break;
                case AgentServiceLifecycleState.Failed:
                    SetStatus(ServiceStopPending, 0, ErrorServiceSpecificError, (uint)Math.Max(1, snapshot.RuntimeExitCode), 1000);
                    break;
            }
        }

        private void SetStatus(
            uint currentState,
            uint controlsAccepted,
            uint win32ExitCode,
            uint serviceSpecificExitCode,
            uint waitHint)
        {
            _status = new ServiceStatus
            {
                ServiceType = ServiceWin32OwnProcess,
                CurrentState = currentState,
                ControlsAccepted = controlsAccepted,
                Win32ExitCode = win32ExitCode,
                ServiceSpecificExitCode = serviceSpecificExitCode,
                CheckPoint = currentState is ServiceStartPending or ServiceStopPending
                    ? (uint)Interlocked.Increment(ref _checkpoint)
                    : 0,
                WaitHint = waitHint
            };
            SetServiceStatus(_statusHandle, ref _status);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ServiceTableEntry
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? ServiceName;

            public ServiceMainFunction? ServiceMain;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatus
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void ServiceMainFunction(int argumentCount, nint arguments);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint HandlerFunction(uint control, uint eventType, nint eventData, nint context);

        [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);

        [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern nint RegisterServiceCtrlHandlerEx(
            string serviceName,
            HandlerFunction handler,
            nint context);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetServiceStatus(nint statusHandle, ref ServiceStatus serviceStatus);
    }
}
