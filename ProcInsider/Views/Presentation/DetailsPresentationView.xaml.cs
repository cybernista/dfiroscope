using System.Windows;
using System.Windows.Controls;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Presentation;

public partial class DetailsPresentationView : UserControl
{
    public DetailsPresentationView() => InitializeComponent();
}

public sealed class DetailsAiTemplateSelector : DataTemplateSelector
{
    public DataTemplate? ProcessTemplate { get; set; }
    public DataTemplate? RecordTemplate { get; set; }

    public override DataTemplate? SelectTemplate(object item, DependencyObject container) =>
        item is ProcessPresentationViewModel ? ProcessTemplate : RecordTemplate;
}
