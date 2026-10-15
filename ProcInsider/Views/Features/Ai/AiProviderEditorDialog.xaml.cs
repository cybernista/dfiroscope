using System.Windows;
using ProcInsider.ViewModels;
namespace ProcInsider.Views.Features.Ai;

/// <summary>One shared Add/Edit form; translates WPF events and clears transient password controls.</summary>
public partial class AiProviderEditorDialog : Window
{
    private readonly AiInvestigationViewModel _viewModel;
    public AiProviderEditorDialog(AiInvestigationViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        Loaded += async (_, _) => { if (viewModel.IsEditing) await viewModel.LoadModelsAsync(null); };
        viewModel.EditorDestinationChanged += DestinationChanged;
        Closed += (_, _) =>
        {
            viewModel.EditorDestinationChanged -= DestinationChanged;
            viewModel.CancelConnectionTest();
            ClearPasswords();
        };
    }
    private void ClearPasswords() { ApiKeyInput.Clear(); FirstPasswordInput.Clear(); }
    private void DestinationChanged(object? sender, EventArgs e) => ClearPasswords();
    private void ApiKeyChanged(object sender, RoutedEventArgs e) => _viewModel?.CancelConnectionTest();
    private async void LoadModelsClicked(object sender, RoutedEventArgs e)
    {
        var key = ApiKeyInput.Password;
        try { await _viewModel.LoadModelsAsync(key); }
        finally { key = string.Empty; }
    }
    private async void TestClicked(object sender, RoutedEventArgs e)
    {
        var key = ApiKeyInput.Password;
        try { await _viewModel.TestConnectionWithKeyAsync(key); }
        finally { key = string.Empty; }
    }
    private void SaveClicked(object sender, RoutedEventArgs e)
    {
        try { if (_viewModel.SaveProfile(ApiKeyInput.Password, FirstPasswordInput.Password)) DialogResult = true; }
        finally { ClearPasswords(); }
    }
}
