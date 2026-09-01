using System.Text;
using System.Windows;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider;

public partial class CrashReportDialog : Window
{
    private readonly string _copyText;

    public CrashReportDialog(
        CrashDiagnosticWriteResult result,
        CrashDiagnosticEntryPoint entryPoint,
        CrashDiagnosticContext context)
    {
        InitializeComponent();

        var path = string.IsNullOrWhiteSpace(result.DiagnosticPath)
            ? "Unavailable"
            : result.DiagnosticPath;
        Title = $"{result.Incident?.ProductDisplayName ?? ProductIdentity.DisplayName} encountered a fatal error";
        var captureWarning = context.AgentConnectedSnapshot == true || context.CaptureActiveSnapshot == true
            ? " An independently running agent or capture may still be active. After restarting, reconnect to verify it and stop it normally if needed."
            : string.Empty;
        SummaryText.Text =
            "A local, privacy-filtered incident record was attempted before shutdown. No report was transmitted. " +
            "Copy the details now; the fatal reporting flow is limited to 45 seconds before shutdown." +
            captureWarning;
        IncidentIdText.Text = result.IncidentId;
        DiagnosticPathText.Text = path;
        EntryPointText.Text = entryPoint.ToString();

        var exception = result.Incident?.Exception;
        var details = new StringBuilder()
            .AppendLine($"Incident: {result.IncidentId}")
            .AppendLine($"UTC time: {result.TimestampUtc:O}")
            .AppendLine($"Entry point: {entryPoint}")
            .AppendLine($"Diagnostic file: {path}")
            .AppendLine($"Exception: {exception?.Type ?? "Unavailable"}")
            .AppendLine($"Message: {exception?.Message ?? "Unavailable"}");
        if (!string.IsNullOrWhiteSpace(result.WriteFailure))
        {
            details.AppendLine($"Diagnostic write failure: {result.WriteFailure}");
        }

        if (!string.IsNullOrWhiteSpace(captureWarning))
        {
            details.AppendLine(captureWarning.Trim());
        }

        _copyText = details.ToString().TrimEnd();
        DetailsText.Text = _copyText;
    }

    private void CopyDetails_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_copyText);
            CopyStatusText.Text = "Copied.";
        }
        catch
        {
            CopyStatusText.Text = "Clipboard unavailable; select the text and press Ctrl+C.";
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
