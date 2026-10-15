using System.Windows.Controls;
using System.Windows;
using ProcInsider.ViewModels;
namespace ProcInsider.Views.Features.Ai;

public partial class ExplorerAiView : UserControl
{
    public ExplorerAiView() => InitializeComponent();
    private AiInvestigationViewModel? Providers => DataContext as AiInvestigationViewModel;
    private void ShowEditor(AiInvestigationViewModel vm)
    {
        var dialog = new AiProviderEditorDialog(vm) { Owner = Window.GetWindow(this) };
        dialog.ShowDialog();
    }
    private void NewProviderClicked(object sender, RoutedEventArgs e)
    {
        if (Providers is { } vm && vm.TryBeginNewProfileDialog()) ShowEditor(vm);
    }
    private void EditProviderClicked(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { CommandParameter: AiProviderProfileRow row } && Providers is { } vm && vm.TryBeginEditProfileDialog(row))
            ShowEditor(vm);
    }
    private void VaultClicked(object sender, RoutedEventArgs e)
    {
        if (Providers is not { } vm || !vm.TryOpenKeystoreDialog(false)) return;
        if (vm.IsVaultUnlocked) vm.Lock();
        else new AiKeystoreDialog(vm, false) { Owner = Window.GetWindow(this) }.ShowDialog();
    }
    private void ChangePasswordClicked(object sender, RoutedEventArgs e)
    {
        if (Providers is { } vm && vm.TryOpenKeystoreDialog(true)) new AiKeystoreDialog(vm, true) { Owner = Window.GetWindow(this) }.ShowDialog();
    }
    private async void ProviderModelsOpened(object sender, EventArgs e)
    {
        if (sender is ComboBox { DataContext: AiProviderProfileRow row } && Providers is { } vm)
            await vm.LoadProfileModelsAsync(row);
    }
    private void ProviderModelChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not ComboBox { DataContext: AiProviderProfileRow row, SelectedItem: string model } combo || row.IsRefreshingModels || Providers is not { } vm) return;
        if (!vm.SetProfileModel(row, model)) combo.SetCurrentValue(ComboBox.SelectedItemProperty, row.ModelName);
    }
    private void ProfileRadioChecked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { DataContext: AiProviderProfileRow row } && row.IsAvailable) Providers?.SelectProfile(row);
    }
}
