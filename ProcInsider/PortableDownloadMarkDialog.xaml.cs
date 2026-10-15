using System.Windows;
using ProcInsider.Services;

namespace ProcInsider;

public partial class PortableDownloadMarkDialog : Window
{
    internal PortableDownloadMarkDialog(PortableDownloadMarkScan scan)
    {
        InitializeComponent();
        FilesList.ItemsSource = scan.Files.Select(file => file.RelativePath).ToArray();
        if (scan.Warnings.Count > 0)
        {
            WarningsText.Text = $"Inspection could not check {scan.Warnings.Count} item(s). " +
                "Those files will not be changed.";
            WarningsText.Visibility = Visibility.Visible;
        }
    }

    private void Skip_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Remove_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
