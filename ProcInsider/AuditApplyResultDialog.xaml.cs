using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class AuditApplyResultDialog : Window
{
    public AuditApplyResultDialog(AuditApplyResultViewModel result)
    {
        DataContext = result;
        InitializeComponent();
    }
}
