using System.IO;
using ProcInsider.Cli;
using ProcInsider.Services.Features;

namespace ProcInsider;

internal static class Program
{
    private const string ProcessCancellationProbeReadyEventVariable =
        "DFIROSCOPE_VIEWER_CLI_SELFTEST_CANCEL_READY_EVENT";

    [STAThread]
    private static int Main(string[] args)
    {
        if (ViewerProcessModeRouter.Select(args) == ViewerProcessMode.Gui)
        {
            var application = new App();
            application.InitializeComponent();
            return application.Run();
        }

        WindowsConsoleSession.EnsureForCommandLine();
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler? cancelHandler = null;
        if (!CliParser.IsShellEntry(args))
        {
            cancelHandler = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            Console.CancelKeyPress += cancelHandler;
        }
        try
        {
            WaitForProcessCancellationProbe(cancellation.Token);
            var featureCatalog = CurrentEducationalReleaseProfile.RuntimeCatalog;
            return ViewerCliApplication.RunAsync(
                    args,
                    featureCatalog,
                    new SystemCliConsole(),
                    new SystemCliClock(),
                    () => new DefaultCliCommandHandlerFactory(
                        featureCatalog),
                    cancellation.Token,
                    () => new SystemCliInterruptSource())
                .GetAwaiter()
                .GetResult();
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return (int)CliExitCode.Canceled;
        }
        catch
        {
            Console.Error.WriteLine("DFIRoscope Live command processing failed internally.");
            return (int)CliExitCode.Failure;
        }
        finally
        {
            if (cancelHandler != null)
            {
                Console.CancelKeyPress -= cancelHandler;
            }
        }
    }

    private static void WaitForProcessCancellationProbe(CancellationToken cancellationToken)
    {
        var eventName = Environment.GetEnvironmentVariable(
            ProcessCancellationProbeReadyEventVariable);
        if (string.IsNullOrWhiteSpace(eventName))
        {
            return;
        }

        try
        {
            using var ready = EventWaitHandle.OpenExisting(eventName);
            ready.Set();
            cancellationToken.WaitHandle.WaitOne(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex) when (ex is
            WaitHandleCannotBeOpenedException or
            UnauthorizedAccessException or
            IOException)
        {
        }
    }
}
