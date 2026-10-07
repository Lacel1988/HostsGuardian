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
        void ActivateNotification(string page)
        {
            Show(); WindowState = WindowState.Normal; Activate();
            if (page == "Policy") viewModel.PolicyWorkspaceCommand.Execute(null);
            else viewModel.OpenNotification(new("activation", Services.NotificationCategory.EngineDns,
                Services.NotificationSeverity.Information, "", "", page));
        }
        Services.WindowsNotificationSink.Instance.Activated += ActivateNotification;
        Loaded += (_, _) => Services.WindowsNotificationSink.Instance.ConsumePending();
        Closed += (_, _) => { Services.WindowsNotificationSink.Instance.Activated -= ActivateNotification; viewModel.Dispose(); };
    }
}
