using System.Windows;

namespace HostsGuardian.Wpf;

public partial class MainWindow : Window
{
    private void EngineSettings_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is HostsGuardian.Wpf.ViewModels.MainViewModel vm) vm.OpenEngineSettings();
    }
    public MainWindow()
    {
        InitializeComponent();
    }
}
