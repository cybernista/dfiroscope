using System.Windows;
using System.Windows.Input;
using ProcInsider.ViewModels;
namespace ProcInsider.Views.Features.Ai;

public partial class AiKeystoreDialog : Window
{
    private readonly AiInvestigationViewModel _viewModel;
    private readonly bool _changePassword;
    public AiKeystoreDialog(AiInvestigationViewModel viewModel, bool changePassword)
    {
        InitializeComponent();
        _viewModel = viewModel; _changePassword = changePassword; DataContext = viewModel;
        Title = changePassword ? "Change Keystore password" : viewModel.IsPasswordConfigured ? "Unlock Keystore" : "Create Keystore password / migrate saved keys";
        ApplyButton.Content = changePassword ? "Change password" : viewModel.IsPasswordConfigured ? "Unlock" : "Create and unlock";
        PasswordLabel.Text = changePassword ? "Old password" : viewModel.IsPasswordConfigured ? "Password" : "New keystore password";
        NewPasswordPanel.Visibility = changePassword ? Visibility.Visible : Visibility.Collapsed;
        Loaded += (_, _) =>
        {
            FocusManager.SetFocusedElement(this, PasswordInput);
            PasswordInput.Focus();
        };
        Closed += (_, _) => ClearPasswords();
    }
    private void ClearPasswords() { PasswordInput.Clear(); NewPasswordInput.Clear(); }
    private void ApplyClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            var succeeded = _changePassword
                ? _viewModel.ChangePassword(PasswordInput.Password, NewPasswordInput.Password)
                : _viewModel.Unlock(PasswordInput.Password);
            if (succeeded) Close();
        }
        finally { ClearPasswords(); }
    }
}
