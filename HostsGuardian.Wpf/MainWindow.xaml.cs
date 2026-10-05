using System.Windows;

namespace HostsGuardian.Wpf;

public partial class MainWindow : Window
{
    private void EngineSettings_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is HostsGuardian.Wpf.ViewModels.MainViewModel vm) vm.OpenEngineSettings();
    }
    private void Notification_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is HostsGuardian.Wpf.ViewModels.MainViewModel vm && sender is System.Windows.FrameworkElement { DataContext: HostsGuardian.Wpf.Services.NotificationItem item }) vm.OpenNotification(item);
    }
    public MainWindow() : this(new HostsGuardian.Wpf.ViewModels.MainViewModel()) { }
    public MainWindow(HostsGuardian.Wpf.ViewModels.MainViewModel viewModel)
    {
        InitializeComponent(); DataContext = viewModel;
        Closed += (_, _) => viewModel.Dispose();
    }
}
