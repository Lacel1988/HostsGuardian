using System.Windows;
using HostsGuardian.Wpf.Localization;
using HostsGuardian.Wpf.Services;
namespace HostsGuardian.Wpf;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        LocalizationService.Instance.ChangeLanguage(UiPreferences.Current.Data.Language, false);
#if DEBUG
        // Local milestone review: use the real selector/binding; never trigger a policy command.
        if (e.Args.Contains("--review-languages"))
        {
            LocalizationService.Instance.ChangeLanguage("en", false);
            Activated += ReviewLanguages;
        }
#endif
        base.OnStartup(e);
    }
#if DEBUG
    private void ReviewLanguages(object? sender, EventArgs e)
    {
        if (MainWindow is not MainWindow window) return;
        Activated -= ReviewLanguages;
        var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            if (window.IsLoaded && window.FindName("LanguageSelector") is System.Windows.Controls.ComboBox selector)
                selector.SelectedValue = "hu";
        };
        timer.Start();
    }
#endif
}
