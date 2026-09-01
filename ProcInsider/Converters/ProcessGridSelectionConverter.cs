using System.Globalization;
using System.Windows.Data;
using ProcInsider.ViewModels;

namespace ProcInsider.Converters;

/// <summary>Only materialized process rows may enter selected-process fan-out.</summary>
public sealed class ProcessGridSelectionConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value as ProcessRowViewModel;

    public object? ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value as ProcessRowViewModel;
}
