using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
namespace ProcInsider.Views.Features.Ai;
public partial class AiTechnicalDetailsView : UserControl
{
    public static readonly DependencyProperty OpenOriginalCommandProperty = DependencyProperty.Register(
        nameof(OpenOriginalCommand), typeof(ICommand), typeof(AiTechnicalDetailsView));
    public ICommand? OpenOriginalCommand { get => (ICommand?)GetValue(OpenOriginalCommandProperty); set => SetValue(OpenOriginalCommandProperty, value); }
    public AiTechnicalDetailsView() => InitializeComponent();
}