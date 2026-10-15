using System.Windows;
using System.Windows.Controls;
using ProcInsider.ViewModels;
namespace ProcInsider.Views.Features.Ai;
public sealed class AiTechnicalTemplateSelector : DataTemplateSelector
{
    public DataTemplate? General { get; set; }
    public DataTemplate? Object { get; set; }
    public DataTemplate? Investigation { get; set; }
    public override DataTemplate? SelectTemplate(object item, DependencyObject container) => item switch
    {
        AiChatViewModel => General,
        ProcessConversationViewModel => Object,
        InvestigationDataViewModel => Investigation,
        _ => null
    };
}