using System.Windows;
using System.Windows.Input;

namespace ProcInsider;

public enum AgentShutdownConfirmationChoice
{
    Cancel = 0,
    Terminate = 1,
    LeaveRunning = 2
}

/// <summary>
/// Presents the Viewer-close Agent shutdown decision. Selected-row termination uses
/// an inline exact-row confirmation because a Medium-integrity Viewer cannot reliably
/// place a modal window above every elevated diagnostic window.
/// </summary>
public partial class AgentShutdownConfirmationDialog : Window
{
    public AgentShutdownConfirmationDialog(string prompt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prompt);
        InitializeComponent();

        PromptText.Text = prompt;
        Title = "Close Agent?";
        TerminateButton.Content = "Terminate Agent and Close";
    }

    public AgentShutdownConfirmationChoice Choice { get; private set; } =
        AgentShutdownConfirmationChoice.Cancel;

    public static AgentShutdownConfirmationChoice ShowForViewerClose(
        Window? owner,
        string prompt)
    {
        var dialog = new AgentShutdownConfirmationDialog(prompt);
        if (owner is { IsVisible: true })
        {
            dialog.Owner = owner;
        }

        dialog.ShowDialog();
        return dialog.Choice;
    }

    private void Window_ContentRendered(object? sender, EventArgs e)
    {
        Activate();
        Keyboard.Focus(CancelButton);
    }

    private void TerminateButton_Click(object sender, RoutedEventArgs e)
    {
        Choice = AgentShutdownConfirmationChoice.Terminate;
        DialogResult = true;
    }

    private void LeaveRunningButton_Click(object sender, RoutedEventArgs e)
    {
        Choice = AgentShutdownConfirmationChoice.LeaveRunning;
        DialogResult = true;
    }
}
