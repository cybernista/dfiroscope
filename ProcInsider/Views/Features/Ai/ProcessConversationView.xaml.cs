using System.Windows;
using System.Windows.Controls;
namespace ProcInsider.Views.Features.Ai;
public partial class ProcessConversationView : UserControl
{
    public static readonly DependencyProperty ShowEvidenceDetailsProperty = DependencyProperty.Register(
        nameof(ShowEvidenceDetails), typeof(bool), typeof(ProcessConversationView), new PropertyMetadata(true));
    public bool ShowEvidenceDetails { get => (bool)GetValue(ShowEvidenceDetailsProperty); set => SetValue(ShowEvidenceDetailsProperty, value); }
    public ProcessConversationView() => InitializeComponent();
}