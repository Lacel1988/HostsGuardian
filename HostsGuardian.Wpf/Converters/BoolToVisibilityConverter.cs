using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace HostsGuardian.Wpf.Converters
{
    public class BoolToVisibilityConverter : IValueConverter
    {
        public bool Invert { get; set; }
        public bool CollapseWhenFalse { get; set; } = true;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool isVisible = value is bool b && b;

            if (parameter?.ToString() == "invert")
                isVisible = !isVisible;

            if (Invert)
                isVisible = !isVisible;

            if (isVisible)
                return Visibility.Visible;

            return CollapseWhenFalse
                ? Visibility.Collapsed
                : Visibility.Hidden;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is Visibility v && v == Visibility.Visible;
        }
    }
}
