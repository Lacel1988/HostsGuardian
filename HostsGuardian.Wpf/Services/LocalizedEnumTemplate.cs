using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

namespace HostsGuardian.Wpf.Services;

/// <summary>Display-only localization; selected enum values remain the contract values.</summary>
public sealed class LocalizedEnumTemplate : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) => L.T(values[0]?.ToString() ?? "");
    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
    public static DataTemplate Create()
    {
        var text = new FrameworkElementFactory(typeof(TextBlock));
        var binding = new MultiBinding { Converter = new LocalizedEnumTemplate() };
        binding.Bindings.Add(new Binding()); binding.Bindings.Add(new Binding(nameof(L.Language)) { Source = L.Instance });
        text.SetBinding(TextBlock.TextProperty, binding); return new DataTemplate { VisualTree = text };
    }
}
