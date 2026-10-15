using System.Configuration;
using System.Data;
using System.Text;
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

    internal async Task OfferPortableDownloadMarkRemovalAsync(MainWindow window)
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return;
        }

        var service = new PortableDownloadMarkService(AppContext.BaseDirectory, processPath);
        PortableDownloadMarkScan? scan;
        try
        {
            scan = await Task.Run(service.Inspect);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Portable download-marker inspection failed: {ex}");
            return;
        }

        if (scan == null || !window.IsVisible || MainWindow != window)
        {
            return;
        }

        if (scan.Files.Count == 0)
        {
            var details = string.Join(Environment.NewLine, scan.Warnings.Take(12));
            MessageBox.Show(window,
                "Windows download-marker inspection could not verify one or more packaged program files. " +
                "No markers were removed. Check file access and the package before starting the Agent." +
                (details.Length == 0 ? "" : Environment.NewLine + Environment.NewLine + details),
                "Downloaded DFIRoscope files", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        bool? consent;
        try
        {
            consent = new PortableDownloadMarkDialog(scan) { Owner = window }.ShowDialog();
        }
        catch (InvalidOperationException ex)
        {
            System.Diagnostics.Debug.WriteLine($"Portable download-marker prompt could not open: {ex}");
            return;
        }

        if (consent != true)
        {
            service.ApplyDecision(scan, PortableDownloadMarkDecision.Skip);
            return;
        }

        PortableDownloadMarkRemovalResult result;
        try
        {
            result = await Task.Run(() => service.ApplyDecision(
                scan, PortableDownloadMarkDecision.Remove));
        }
        catch (Exception ex)
        {
            if (window.IsVisible)
            {
                MessageBox.Show(window,
                    $"Windows download-marker removal stopped: {ex.Message}",
                    "Downloaded DFIRoscope files", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            return;
        }

        if (!window.IsVisible)
        {
            return;
        }

        var message = new StringBuilder()
            .AppendLine($"Removed Zone.Identifier from {result.Removed.Count} file(s).")
            .AppendLine($"Already absent: {result.AlreadyAbsent.Count}.")
            .AppendLine($"Failed: {result.Failed.Count}.");
        if (result.Failed.Count > 0 || scan.Warnings.Count > 0)
        {
            message.AppendLine().AppendLine("Details:");
            foreach (var detail in result.Failed.Concat(scan.Warnings).Take(12))
            {
                message.AppendLine(detail);
            }

            var remaining = result.Failed.Count + scan.Warnings.Count - 12;
            if (remaining > 0)
            {
                message.AppendLine($"And {remaining} more item(s).");
            }
        }

        MessageBox.Show(window, message.ToString(), "Downloaded DFIRoscope files",
            MessageBoxButton.OK,
            result.Failed.Count > 0 || scan.Warnings.Count > 0
                ? MessageBoxImage.Warning
                : MessageBoxImage.Information);
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
