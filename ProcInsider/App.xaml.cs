using System.Configuration;
using System.Data;
using System.Windows;
using System.Windows.Threading;
using ProcInsider.Services;

namespace ProcInsider;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    private readonly CrashDiagnosticService _crashDiagnostics = new();
    private readonly ViewerFatalErrorCoordinator _fatalErrors;
    private int _fatalShutdownStarted;
    private System.Threading.Timer? _fatalShutdownTimer;
    private string _viewerLifecycleState = "Startup";

    public App()
    {
        _fatalErrors = new ViewerFatalErrorCoordinator(_crashDiagnostics);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _viewerLifecycleState = "Running";
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _viewerLifecycleState = "ShuttingDown";
        DispatcherUnhandledException -= OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException -= OnAppDomainUnhandledException;
        TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(
        object sender,
        DispatcherUnhandledExceptionEventArgs args)
    {
        // Handled only to persist/show the incident and initiate controlled
        // shutdown. Execution never returns to the normal viewer workflow.
        args.Handled = true;
        HandleFatalException(args.Exception, CrashDiagnosticEntryPoint.Dispatcher);
    }

    private void OnAppDomainUnhandledException(object? sender, UnhandledExceptionEventArgs args)
    {
        var exception = args.ExceptionObject as Exception ??
            new InvalidOperationException("A non-Exception object reached the AppDomain unhandled-exception boundary.");
        HandleFatalException(exception, CrashDiagnosticEntryPoint.AppDomain);
        // The runtime owns process termination for this entry point. Do not send
        // agent shutdown, cancellation, or evidence-write commands here.
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs args)
    {
        try
        {
            _crashDiagnostics.Record(
                args.Exception,
                CrashDiagnosticEntryPoint.TaskScheduler,
                CreateCrashDiagnosticContext());
        }
        finally
        {
            // The task is already abandoned. Observing here prevents repeated
            // finalizer escalation without showing modal UI or closing the app.
            args.SetObserved();
        }
    }

    private void HandleFatalException(Exception exception, CrashDiagnosticEntryPoint entryPoint)
    {
        var context = CreateCrashDiagnosticContext();
        _fatalErrors.Handle(exception, entryPoint, context,
            result => TryShowFatalSurface(result, entryPoint, context),
            FatalErrorSurface.ShowFallback,
            entryPoint == CrashDiagnosticEntryPoint.Dispatcher
                ? RequestFatalShutdown
                : () => { }); // AppDomain termination belongs to the runtime.
    }

    private CrashDiagnosticContext CreateCrashDiagnosticContext()
    {
        try
        {
            if (MainWindow is MainWindow mainWindow)
            {
                return mainWindow.CreateCrashDiagnosticContext(_viewerLifecycleState);
            }
        }
        catch
        {
            // Startup and terminal paths use a context that cannot reference a
            // session or archived capture.
        }

        return new CrashDiagnosticContext
        {
            ViewerLifecycleState = _viewerLifecycleState
        };
    }

    private static bool TryShowFatalSurface(
        CrashDiagnosticWriteResult result,
        CrashDiagnosticEntryPoint entryPoint,
        CrashDiagnosticContext context)
        => FatalErrorSurface.TryShowReport(result, entryPoint, context);

    private void RequestFatalShutdown()
    {
        if (Interlocked.CompareExchange(ref _fatalShutdownStarted, 1, 0) != 0)
        {
            return;
        }

        _viewerLifecycleState = "FatalShutdown";
        // A broken layout/Closing handler must not keep the failed Viewer alive.
        // This exits only this process; it has no independent Agent capability.
        _fatalShutdownTimer = new System.Threading.Timer(_ => Environment.Exit(-1), null,
            TimeSpan.FromSeconds(5), Timeout.InfiniteTimeSpan);
        try
        {
            (MainWindow as MainWindow)?.PrepareForFatalShutdown();
        }
        catch
        {
            // Continue to the simplest safe shutdown path.
        }

        try
        {
            Shutdown(-1);
        }
        catch
        {
            Environment.Exit(-1);
        }
    }
}
