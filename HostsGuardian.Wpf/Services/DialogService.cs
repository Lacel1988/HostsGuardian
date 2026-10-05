using L = HostsGuardian.Wpf.Localization.LocalizationService;
using System.Windows;

namespace HostsGuardian.Wpf.Services;

public sealed class DialogService : IDialogService
{
    public void Info(string message, string title = "Info")
        => LocalizedDialogs.Show(L.T(message), L.T(title));

    public void Error(string message, string title = "Error")
        => LocalizedDialogs.Show(L.T(message), L.T(title));
}
