using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace HostsGuardian.Wpf.Converters
{
    public sealed class BoolToVisibilityConverter : IValueConverter
    {
        public bool Invert { get; set; }
        public bool CollapseWhenFalse { get; set; } = true;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool b;

            if (value is bool bb)
            {
                b = bb;
            }
            else if (value is null)
            {
                b = false;
            }
            else
            {
                // Covers bool? boxed cases and odd bindings
                var s = value.ToString();
                b = string.Equals(s, "True", StringComparison.OrdinalIgnoreCase);
            }

            if (parameter is string p && string.Equals(p, "invert", StringComparison.OrdinalIgnoreCase))
                b = !b;

            if (Invert) b = !b;

            if (b) return Visibility.Visible;
            return CollapseWhenFalse ? Visibility.Collapsed : Visibility.Hidden;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is Visibility v)
            {
                var b = v == Visibility.Visible;
                return Invert ? !b : b;
            }

            return false;
        }
    }
}