using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Features.SelectedProcess;

public partial class DataProcessAppInfoView : UserControl
{
    private readonly List<TabItem> _extensionTabs = [];

    public DataProcessAppInfoView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(
        object sender,
        DependencyPropertyChangedEventArgs e)
    {
        foreach (var tab in _extensionTabs)
        {
            tab.RemoveHandler(
                Selector.SelectedEvent,
                (RoutedEventHandler)OnExtensionTabSelected);
            AppInfoTabControl.Items.Remove(tab);
        }

        _extensionTabs.Clear();
        if (e.NewValue is not MainViewModel viewModel)
        {
            return;
        }

        foreach (var descriptor in viewModel.AppInfoExtensionTabs)
        {
            var tab = new TabItem
            {
                DataContext = descriptor
            };
            tab.SetBinding(
                HeaderedContentControl.HeaderProperty,
                new Binding(nameof(FeatureTabDescriptor.Header))
                {
                    Source = descriptor,
                    Mode = BindingMode.OneWay
                });
            tab.AddHandler(
                Selector.SelectedEvent,
                (RoutedEventHandler)OnExtensionTabSelected);
            _extensionTabs.Add(tab);
            AppInfoTabControl.Items.Add(tab);
        }
    }

    private static void OnExtensionTabSelected(object sender, RoutedEventArgs e)
    {
        if (!ReferenceEquals(sender, e.OriginalSource) ||
            sender is not TabItem { DataContext: FeatureTabDescriptor descriptor } tab ||
            tab.Content != null)
        {
            return;
        }

        if (descriptor.TryActivate(out var content, out var activationException))
        {
            tab.Content = content;
            return;
        }

        tab.Content = new TextBlock
        {
            Margin = new Thickness(10),
            TextWrapping = TextWrapping.Wrap,
            Text = $"{descriptor.BaseHeader} is unavailable: " +
                   (activationException?.Message ?? "activation failed")
        };
    }
}
