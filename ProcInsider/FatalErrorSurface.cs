using System.Runtime.InteropServices;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider;

/// <summary>Fatal UI never dispatches onto, or takes ownership from, the failed window.</summary>
public static class FatalErrorSurface
{
    public static bool TryShowReport(CrashDiagnosticWriteResult result,
        CrashDiagnosticEntryPoint entryPoint, CrashDiagnosticContext context) =>
        RunOnIsolatedThread(() => new CrashReportDialog(result, entryPoint, context).ShowDialog(),
            TimeSpan.FromSeconds(30));

    public static void ShowFallback(CrashDiagnosticWriteResult result) =>
        RunOnIsolatedThread(() =>
        {
            // MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST. No owner,
            // service notification, desktop switch, or message to the damaged grid.
            if (MessageBoxW(IntPtr.Zero, CreateFallbackText(result),
                    $"{ProductIdentity.DisplayName} fatal error", 0x00050010) == 0)
            {
                throw new InvalidOperationException("Windows could not display the fatal error indication.");
            }
        }, TimeSpan.FromSeconds(15));

    public static string CreateFallbackText(CrashDiagnosticWriteResult result) =>
        "The Viewer encountered a fatal error and will close. No report was transmitted.\n\n" +
        $"Incident: {Bound(result.IncidentId, 128)}\n" +
        $"Diagnostic file: {Bound(result.DiagnosticPath ?? "Unavailable (incident write failed)", 2048)}\n\n" +
        "An independent Agent or capture may still be running. Restart the Viewer and reconnect to verify it.\n\n" +
        "Press Ctrl+C to copy this message. This fallback closes with the Viewer after at most 15 seconds.";

    // Public for deterministic timeout/failure tests; this has no Agent/evidence capability.
    public static bool RunOnIsolatedThread(Action show, TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var completed = false;
        var thread = new Thread(() =>
        {
            try
            {
                show();
                completed = true;
            }
            catch
            {
                // Do not allow this reporting thread to create an AppDomain failure.
            }
        }) { IsBackground = true, Name = "DFIRoscope fatal error surface" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return thread.Join(timeout) && completed;
    }

    private static string Bound(string value, int maximum) =>
        value.Length <= maximum ? value : value[..maximum] + "...";

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int MessageBoxW(IntPtr owner, string text, string caption, uint type);
}
