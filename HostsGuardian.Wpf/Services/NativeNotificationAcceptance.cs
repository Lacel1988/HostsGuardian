using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Toolkit.Uwp.Notifications;
using HostsGuardian.Wpf.ViewModels;
using HostsGuardian.Core.Services;

namespace HostsGuardian.Wpf.Services;

/// <summary>Explicit labeled desktop transport check; no production connection, delivery or configuration.</summary>
public static class NativeNotificationAcceptance
{
    public static Window Start()
    {
        var directory = Path.Combine(Path.GetTempPath(), "HostsGuardian-native-acceptance-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var vm = new MainViewModel(new ConfigService(Path.Combine(directory,"config.json")), false,
            new AuditLogService(Path.Combine(directory,"audit.log")));
        var window = new MainWindow(vm) { Title="HostsGuardian — Windows notification acceptance (isolated check)" };
        Application.Current.MainWindow=window;
        window.Show(); window.WindowState=WindowState.Minimized;
        var key = "acceptance.native."+Guid.NewGuid().ToString("N");
        var item = new NotificationItem(key,NotificationCategory.EngineDns,NotificationSeverity.Information,
            "Windows notification acceptance check", "This is a labeled notification delivery check. No production policy or network configuration changed.","Router");
        var activated=false;
        WindowsNotificationSink.Instance.Activated += Record;
        void Record(string page) { activated=true; Write(); }
        void Write()
        {
            try
            {
                var history=ToastNotificationManagerCompat.History.GetHistory();
                File.WriteAllText(Path.Combine(directory,"native-result.json"),JsonSerializer.Serialize(new
                { Kind="LABELED_TRANSPORT_CHECK_NOT_PRODUCTION_ACCEPTANCE", WindowsSetting=ToastNotificationManagerCompat.CreateToastNotifier().Setting.ToString(),
                    ToastHistoryContainsCheck=history.Any(t=>t.Content.GetXml().Contains(item.Title)), ClickActivationObserved=activated,
                    WindowsNotificationSink.Instance.LastFailure, BannerVisibility="HUMAN_REVIEW_REQUIRED", ProductionMutation=false }));
            }
            catch (Exception e) { File.WriteAllText(Path.Combine(directory,"native-result.json"),JsonSerializer.Serialize(new { Failure=e.GetType().Name,ProductionMutation=false })); }
        }
        var timer=new DispatcherTimer { Interval=TimeSpan.FromSeconds(3) };
        timer.Tick+=(_,_)=>{timer.Stop();Write();}; timer.Start();
        window.Closed+=(_,_)=>{timer.Stop();Write();WindowsNotificationSink.Instance.Activated-=Record;WindowsNotificationSink.Instance.Remove(key);};
        WindowsNotificationSink.Instance.Show(item);
        return window;
    }
}
