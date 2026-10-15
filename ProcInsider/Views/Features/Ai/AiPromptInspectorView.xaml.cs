using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;

namespace ProcInsider.Views.Features.Ai;
public partial class AiPromptInspectorView : UserControl
{
    public static readonly DependencyProperty LoadCommandProperty = DependencyProperty.Register(nameof(LoadCommand),
        typeof(ICommand), typeof(AiPromptInspectorView), new PropertyMetadata(null, LoadCommandChanged));
    public ICommand? LoadCommand { get => (ICommand?)GetValue(LoadCommandProperty); set => SetValue(LoadCommandProperty, value); }
    private Expander? _expander;
    private bool _loading;
    private bool _waitingForCommand;
    private ICommand? _subscribedCommand;
    public AiPromptInspectorView()
    {
        InitializeComponent();
        Loaded += InspectorLoaded;
        Unloaded += InspectorUnloaded;
        DataContextChanged += InspectorContextChanged;
    }
    private async void InspectorLoaded(object sender, RoutedEventArgs e)
    {
        DependencyObject? ancestor = VisualTreeHelper.GetParent(this);
        while (ancestor != null && ancestor is not Expander) ancestor = VisualTreeHelper.GetParent(ancestor);
        _expander = ancestor as Expander;
        if (_expander == null) return;
        _expander.Expanded += PromptExpanded;
        SubscribeLoadCommand(LoadCommand);
        if (_expander.IsExpanded) await LoadAsync();
    }
    private void InspectorUnloaded(object sender, RoutedEventArgs e)
    {
        if (_expander != null) _expander.Expanded -= PromptExpanded;
        _expander = null;
        _waitingForCommand = false;
        SubscribeLoadCommand(null);
    }
    private async void InspectorContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        LoadStatus.Text = string.Empty;
        _waitingForCommand = false;
        if (_expander?.IsExpanded == true) await LoadAsync();
    }
    private async void PromptExpanded(object sender, RoutedEventArgs e)
    {
        if (ReferenceEquals(e.OriginalSource, _expander)) await LoadAsync();
    }
    private static async void LoadCommandChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    {
        var inspector = (AiPromptInspectorView)sender;
        if (!inspector.IsLoaded) return;
        inspector.SubscribeLoadCommand(e.NewValue as ICommand);
        if (inspector._expander?.IsExpanded == true) await inspector.LoadAsync();
    }
    private void SubscribeLoadCommand(ICommand? command)
    {
        if (ReferenceEquals(command, _subscribedCommand)) return;
        if (_subscribedCommand != null) _subscribedCommand.CanExecuteChanged -= LoadAvailabilityChanged;
        _subscribedCommand = command;
        if (_subscribedCommand != null) _subscribedCommand.CanExecuteChanged += LoadAvailabilityChanged;
    }
    private async void LoadAvailabilityChanged(object? sender, EventArgs e)
    {
        if (_waitingForCommand && _expander?.IsExpanded == true) await LoadAsync();
    }
    private async Task LoadAsync()
    {
        if (_loading || DataContext is not AiConversationMessage message) return;
        if (message.PromptRequests.Count > 0 && message.PromptRequests.All(request => !string.IsNullOrEmpty(request.RequestBody)))
        {
            _waitingForCommand = false;
            return;
        }
        if (LoadCommand is not IAsyncRelayCommand command) return;
        if (!command.CanExecute(message))
        {
            _waitingForCommand = true;
            LoadStatus.Text = "Waiting for saved request…";
            return;
        }
        _waitingForCommand = false;
        _loading = true;
        LoadStatus.Text = "Loading saved request…";
        try
        {
            await command.ExecuteAsync(message);
            if (DataContext is AiConversationMessage current && current.Id == message.Id && current.ConversationId == message.ConversationId)
                LoadStatus.Text = current.PromptRequests.Count > 0 && current.PromptRequests.All(request => !string.IsNullOrEmpty(request.RequestBody))
                    ? string.Empty : "The saved request body is unavailable for this message. Collapse and reopen to retry.";
        }
        catch (Exception)
        {
            if (DataContext is AiConversationMessage current && current.Id == message.Id && current.ConversationId == message.ConversationId)
                LoadStatus.Text = "The saved request could not be loaded. Collapse and reopen to retry.";
        }
        finally
        {
            _loading = false;
            // A recycled visual can receive another message while the previous owner read is pending.
            if (_expander?.IsExpanded == true && DataContext is AiConversationMessage next &&
                (next.Id != message.Id || next.ConversationId != message.ConversationId)) await LoadAsync();
        }
    }
}
