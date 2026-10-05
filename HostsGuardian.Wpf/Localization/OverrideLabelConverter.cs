using System.Globalization;
using System.Windows.Data;
namespace HostsGuardian.Wpf.Localization;
public sealed class OverrideLabelConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) => LocalizationService.T(values[0]?.ToString() ?? "Inherit");
    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => targetTypes.Select(_ => Binding.DoNothing).ToArray();
}
