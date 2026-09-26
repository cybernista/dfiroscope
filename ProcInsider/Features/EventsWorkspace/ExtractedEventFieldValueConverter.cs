using System.Globalization;
using System.Windows.Data;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class ExtractedEventFieldValueConverter : IValueConverter, IMultiValueConverter
{
    internal static readonly ExtractedEventFieldValueConverter Instance = new();
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var identity = parameter as NativeEventColumnIdentity ?? new(null, null, (string)parameter);
        return identity.DisplayValue(value as EventFieldExtraction);
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) => Convert(values[0], targetType, parameter, culture);
    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
