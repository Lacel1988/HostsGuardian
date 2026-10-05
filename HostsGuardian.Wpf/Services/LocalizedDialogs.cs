using System.Windows;
using System.Windows.Controls;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

namespace HostsGuardian.Wpf.Services;

/// <summary>Localized modal consent. Closing, Escape and the default action all decline.</summary>
public static class LocalizedDialogs
{
    public static Window Create(Window? owner, string message, string title, bool confirmation)
    {
        var window = new Window
        {
            Title = L.T(title), Width = 560, SizeToContent = SizeToContent.Height, MaxHeight = 620,
            ResizeMode = ResizeMode.NoResize, WindowStartupLocation = owner == null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
            Resources = new ResourceDictionary { Source = new Uri("/HostsGuardian.Wpf;component/Styles/MatrixStyles.xaml", UriKind.Relative) }
        };
        if (owner?.IsVisible == true) window.Owner = owner;
        var panel = new DockPanel { Margin = new Thickness(20) };
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0,16,0,0) };
        DockPanel.SetDock(actions, Dock.Bottom); panel.Children.Add(actions);
        panel.Children.Add(new ScrollViewer { MaxHeight = 460, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Content = new TextBlock { Text = L.T(message), TextWrapping = TextWrapping.Wrap } });
        if (confirmation)
        {
            var yes = new Button { Name = "ConfirmButton", Content = L.T("Yes"), Margin = new Thickness(0,0,10,0) };
            yes.Click += (_, _) => window.DialogResult = true; actions.Children.Add(yes);
        }
        var decline = new Button { Name = "DeclineButton", Content = L.T(confirmation ? "No" : "OK"), IsCancel = true, IsDefault = true };
        decline.Click += (_, _) => window.DialogResult = false; actions.Children.Add(decline);
        window.Content = panel;
        return window;
    }
    public static bool Confirm(Window? owner, string message, string title) => Create(owner, message, title, true).ShowDialog() == true;
    public static void Show(string message, string title) => Create(Application.Current?.MainWindow, message, title, false).ShowDialog();
}
