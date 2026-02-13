using System.Windows;

namespace HostsGuardian.Wpf.Services;

public sealed class DialogService : IDialogService
{
    public void Info(string message, string title = "Info")
        => MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);

    public void Error(string message, string title = "Error")
        => MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
}
