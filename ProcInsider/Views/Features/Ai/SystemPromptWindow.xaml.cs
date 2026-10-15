using System.Windows;
using ProcInsider.Services.Ai;

namespace ProcInsider.Views.Features.Ai;

public sealed record SystemPromptEditResult(string Instructions, bool AllChatsInSession);

/// <summary>Edits a draft only; the conversation owner validates and saves the returned scope.</summary>
public partial class SystemPromptWindow : Window
{
    public SystemPromptEditResult? Result { get; private set; }

    public SystemPromptWindow(string instructions, bool allChatsInSession = false)
    {
        InitializeComponent();
        InstructionsEditor.Text = instructions;
        AllChats.IsChecked = allChatsInSession;
        ThisChat.IsChecked = !allChatsInSession;
        Loaded += (_, _) => { InstructionsEditor.Focus(); InstructionsEditor.CaretIndex = 0; };
    }

    public static SystemPromptEditResult? Edit(Window? owner, string instructions, bool allChatsInSession = false)
    {
        var editor = new SystemPromptWindow(instructions, allChatsInSession);
        if (owner != null) editor.Owner = owner;
        return editor.ShowDialog() == true ? editor.Result : null;
    }

    private void SaveClicked(object sender, RoutedEventArgs e)
    {
        var instructions = InstructionsEditor.Text;
        try
        {
            AiPromptCatalog.ResolveSystemInstructions(instructions, null);
        }
        catch (ArgumentException error)
        {
            ValidationMessage.Text = error.Message;
            InstructionsEditor.Focus();
            return;
        }
        Result = new(instructions, AllChats.IsChecked == true);
        DialogResult = true;
    }
}
