using System.Windows;

namespace ProcInsider;

public partial class EventTelemetryResultDialog : Window
{
    public EventTelemetryResultDialog(string summary, string details)
    {
        DataContext = new { Summary = summary, Details = details };
        InitializeComponent();
        var area = SystemParameters.WorkArea;
        MaxWidth = Math.Max(1, area.Width - 32);
        MaxHeight = Math.Max(1, area.Height - 32);
        Width = Math.Min(1200, MaxWidth);
        Height = Math.Min(850, MaxHeight);
        MinWidth = Math.Min(640, Width);
        MinHeight = Math.Min(380, Height);
    }
}
