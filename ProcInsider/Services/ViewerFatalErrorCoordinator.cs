namespace ProcInsider.Services;

/// <summary>
/// Incident-first, one-shot terminal flow. Reentrant failures are recorded but do
/// not dismiss the first error surface or initiate a second shutdown.
/// </summary>
public sealed class ViewerFatalErrorCoordinator(CrashDiagnosticService diagnostics)
{
    private int _started;

    public void Handle(
        Exception exception,
        CrashDiagnosticEntryPoint entryPoint,
        CrashDiagnosticContext context,
        Func<CrashDiagnosticWriteResult, bool> showPrimary,
        Action<CrashDiagnosticWriteResult> showFallback,
        Action shutdown)
    {
        // Claim before persistence so even a reentrant reporting failure is bounded.
        var ownsFlow = Interlocked.CompareExchange(ref _started, 1, 0) == 0;
        var result = diagnostics.Record(exception, entryPoint, context);
        if (!ownsFlow)
        {
            return;
        }

        try
        {
            var shown = false;
            try
            {
                shown = showPrimary(result);
            }
            catch
            {
                // The independently implemented fallback does not require WPF.
            }

            if (!shown)
            {
                try
                {
                    showFallback(result);
                }
                catch
                {
                    // The persisted incident is still available after termination.
                }
            }
        }
        finally
        {
            shutdown();
        }
    }
}
