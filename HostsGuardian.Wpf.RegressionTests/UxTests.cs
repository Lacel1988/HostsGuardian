using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf;
using HostsGuardian.Wpf.Services;
using HostsGuardian.Wpf.ViewModels;
using L = HostsGuardian.Wpf.Localization.LocalizationService;
using ActivityEvent = HostsGuardian.Wpf.ViewModels.ActivityEvent;

internal static class UxTests
{
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Pump() => Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
    private sealed class Desktop : IDesktopNotificationSink
    {
        public bool Available => true;
        public int Count;
        public string Message = "";
        public void Show(NotificationItem notification) { Count++; Message = notification.Title; }
    }
    private sealed class BindingErrors : TraceListener
    {
        public readonly List<string> Errors = new();
        public override void Write(string? message) { }
        public override void WriteLine(string? message) { if (message?.Contains("Error:") == true) Errors.Add(message); }
    }
    public static void Run(string? screenshotDirectory)
    {
        var temporary = Path.Combine(Path.GetTempPath(), "HostsGuardian-ux-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        UiPreferences.Use(new UiPreferences(Path.Combine(temporary, "preferences.json")));
        L.Instance.ChangeLanguage("en", false);
        Check(L.English.Keys.Order().SequenceEqual(L.Hungarian.Keys.Order()), "EN/HU resource keys differ");
        foreach (var key in L.English.Keys)
        {
            Check(!string.IsNullOrWhiteSpace(L.Hungarian[key]), "Empty HU resource: " + key);
            var enFormats = Regex.Matches(L.English[key], @"\{\d+(?:[^}]*)\}").Select(m => m.Value).Order();
            var huFormats = Regex.Matches(L.Hungarian[key], @"\{\d+(?:[^}]*)\}").Select(m => m.Value).Order();
            Check(enFormats.SequenceEqual(huFormats), "Placeholder mismatch: " + key);
        }
        Check(L.Instance["missing.key"] == "missing.key", "Missing key not safe");
        Check(L.F("invalid {format", "fixture") == "invalid {format", "Malformed missing resource format was unsafe");
        L.Instance.ChangeLanguage("hu");
        Check(new UiPreferences(Path.Combine(temporary, "preferences.json")).Data.Language == "hu", "Language did not persist");
        Check(L.T("Engine unreachable") == "Az Engine nem érhető el", "HU notification language");
        Check(L.F("Added domain: {0}", "fixture.invalid").Contains("fixture.invalid"), "Formatting lost target");
        Console.WriteLine("PASS EN/HU resource completeness, placeholders, safe fallback and language persistence");

        var prefs = new UiPreferences(Path.Combine(temporary, "notifications.json"));
        var desktop = new Desktop(); var foreground = true;
        var center = new NotificationCenter(prefs, desktop, () => foreground);
        void Observe(bool failed) => center.Observe("engine", failed, NotificationCategory.EngineDns, NotificationSeverity.Critical,
            "Engine unreachable", "HostsGuardian cannot reach the DNS Engine.", "Router");
        Observe(false); Check(center.Items.Count == 0, "Unobserved recovery fabricated");
        Observe(true); Observe(true);
        Check(center.Items.Count == 1 && center.UnreadCount == 1 && center.HasCritical && desktop.Count == 0, "Deduplication/foreground/severity failed");
        Check(center.Items[0].Title == "Az Engine nem érhető el", "Center used another language");
        center.MarkAllRead(); Check(center.UnreadCount == 0 && center.HasCritical, "Read dismissed active critical condition");
        Observe(false); Observe(false);
        Check(center.Items.Count == 2 && center.Items[0].Resolved && !center.HasCritical, "Recovery resolution/deduplication failed");
        L.Instance.ChangeLanguage("en", false); center.Relocalize();
        Check(center.Items[0].Title == "Engine unreachable", "Notification did not relocalize");
        foreground = false; Observe(true);
        Check(desktop.Count == 1 && desktop.Message == "Engine unreachable", "Desktop abstraction lost localization/background routing");
        prefs.SetEnabled(NotificationCategory.NewDevices, false);
        center.Observe("unknown", true, NotificationCategory.NewDevices, NotificationSeverity.Warning, "Unknown device discovered", "", "Devices");
        Check(center.Items.Count == 3, "Preference did not filter warning");
        prefs.SetEnabled(NotificationCategory.EngineDns, false);
        center.Observe("dns", true, NotificationCategory.EngineDns, NotificationSeverity.Critical, "DNS service failure", "", "Router");
        Check(center.HasCritical && desktop.Count == 1, "Preference concealed critical condition or ignored desktop filtering");
        Check(!new UnregisteredDesktopNotificationSink().Available, "Unregistered desktop sink claims support");
        Console.WriteLine("PASS notification severity, deduplication, unread, recovery, preferences and foreground/desktop localization");

        var configPath = Path.Combine(temporary, "config.json");
        var configService = new ConfigService(configPath);
        var deviceId = Guid.NewGuid();
        var config = new AppConfig();
        config.BlockedDomains.Add(new DomainEntry { Domain = "fixture.invalid", DnsBlocked = true, Notes = "Fixture" });
        config.DeviceDomainPolicy = FullDnsPolicy.Empty with
        { Devices = System.Collections.Immutable.ImmutableArray.Create(new DeviceRegistration(deviceId, "Fixture laptop", "02:00:00:00:00:01", "fixture", "Isolated UX fixture")) };
        configService.Save(config); var before = File.ReadAllBytes(configPath);
        var audit = new AuditLogService(Path.Combine(temporary, "audit.log"));
        audit.Write(new ActivityEvent("WPF user action", "Policy", "Removed domain: {0}", new[] { "fixture.invalid" }).Serialize());
        audit.Write("Historical raw warning", "WARN");
        audit.Write("Historical raw exception", "ERROR");
        var vm = new MainViewModel(configService, false, audit);
        vm.Devices.Add(new DeviceVm(new NetworkDevice { Ip = "192.0.2.10", Mac = "02:00:00:00:00:01" }, "Fixture laptop", false) { DeviceId = deviceId, ObservedAtUtc = DateTimeOffset.UtcNow });
        vm.SelectedDevice = vm.Devices[0];
        Check(vm.Notifications.Items.Count == 0, "Initialization fabricated notification");
        var app = new App(); app.InitializeComponent(); app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        L.Instance.ChangeLanguage("hu", false);
        var consent = LocalizedDialogs.Create(null, "Select a public certificate only", "Explicit certificate trust", true);
        var consentButtons = ((DockPanel)consent.Content).Children.OfType<StackPanel>().Single().Children.OfType<Button>().ToArray();
        Check(consentButtons[0].Content?.ToString() == "Igen" && consentButtons[1].Content?.ToString() == "Nem" &&
            !consentButtons[0].IsDefault && consentButtons[1].IsDefault && consentButtons[1].IsCancel, "Localized consent weakened/defaulted approval");
        consent.Close();
        L.Instance.ChangeLanguage("en", false);
        Console.WriteLine("PASS localized confirmation buttons preserve explicit consent and default decline");
        var listener = new BindingErrors(); PresentationTraceSources.DataBindingSource.Listeners.Add(listener);
        var window = new MainWindow(vm) { Width = 1000, Height = 640 }; window.Show(); Pump(); window.UpdateLayout();
        var selector = (ComboBox)window.FindName("LanguageSelector");
        var tabNames = new[] { "DomainsTab", "RouterTab", "DevicesTab", "LogTab" };
        foreach (var language in new[] { "en", "hu", "en", "hu" })
        {
            selector.SelectedValue = language; Pump(); window.UpdateLayout();
            Check(vm.SelectedLanguage == language, "Actual language selector did not commit");
            Check(((TabItem)window.FindName("DevicesTab")).Header?.ToString() == (language == "hu" ? "Eszközök" : "Devices"), "Navigation header did not switch live");
            foreach (var name in tabNames)
            {
                var tab = (TabItem)window.FindName(name); tab.IsSelected = true; Pump(); window.UpdateLayout();
                Check(tab.IsSelected && tab.ActualWidth > 50 && tab.ActualHeight >= 30, "Navigation layout collapsed");
                Check(name switch { "DomainsTab" => vm.IsDomainsVisible, "RouterTab" => vm.IsRouterVisible, "DevicesTab" => vm.IsDevicesVisible, _ => vm.IsLogVisible }, "Navigation VM is stale");
                var bounds = tab.TransformToAncestor(window).TransformBounds(new Rect(tab.RenderSize));
                Check(bounds.Right <= window.ActualWidth && bounds.Bottom <= window.ActualHeight, "Localized navigation exceeds compact window");
                if (screenshotDirectory != null) Render(window, Path.Combine(screenshotDirectory, $"wpf-{language}-{name}.png"));
            }
            var tabs = tabNames.Select(name => (TabItem)window.FindName(name)).ToArray();
            for (var i = 0; i < tabs.Length - 1; i++)
            {
                var a = tabs[i].TransformToAncestor(window).TransformBounds(new Rect(tabs[i].RenderSize));
                var b = tabs[i + 1].TransformToAncestor(window).TransformBounds(new Rect(tabs[i + 1].RenderSize));
                Check(!a.IntersectsWith(b), "Navigation items overlap");
            }
            var controls = Descendants(window).OfType<Button>().Where(b => b.ToolTip != null).ToArray();
            Check(controls.Length >= 2 && controls.All(b => ToolTipService.GetInitialShowDelay(b) == 2500), "Intentional tooltip hover delay missing");
            Check(controls.Any(b => b.ToolTip?.ToString() == L.T("Clears only this PC’s cached DNS answers.")), "Tooltip did not follow language switch");
            var expectedLevels = language == "hu" ? new[] { "INFORMÁCIÓ", "FIGYELMEZTETÉS", "HIBA" } : new[] { "INFO", "WARN", "ERROR" };
            foreach (var item in vm.LogItems)
                Check(item.DisplayLevel == expectedLevels[Array.IndexOf(new[] { "INFO", "WARN", "ERROR" }, item.Level)], "Severity display did not switch");
            vm.SelectedLogLevel = "WARN";
            Check(vm.LogView.Cast<ActivityItemVm>().All(item => item.Level == "WARN") && vm.LogView.Cast<ActivityItemVm>().Any(), "Localized severity broke raw filtering");
            vm.SelectedLogLevel = "ALL";
            Check(new ActivityItemVm(DateTime.UtcNow, "INFO", "Removed domain: fixture.invalid").DisplayMessage == "Removed domain: fixture.invalid", "Historical raw message was translated");
            Check(vm.LogItems.Single(item => item.Event != null).DisplayMessage == (language == "hu" ? "Domain eltávolítva: fixture.invalid" : "Removed domain: fixture.invalid"), "Structured removal did not localize");
            if (language == "hu")
            {
                Check(vm.EngineEffectivePolicy == "Az Engine által alkalmazott szabály ismeretlen; válasszon domaint, majd ellenőrizze.", "Effective policy wording regressed");
                Check(L.T("CHANGES NOT SENT") == "HELYI VÁLTOZÁSOK", "Local changes wording regressed");
            }
            window.Width = 1200; window.Height = 760;
            foreach (var name in new[] { "RouterTab", "LogTab" })
            {
                ((TabItem)window.FindName(name)).IsSelected = true; Pump(); window.UpdateLayout();
                var grids = Descendants(window).OfType<DataGrid>();
                if (name == "RouterTab")
                    Check(grids.SelectMany(grid => grid.Columns).Any(column => column.Header?.ToString() == L.T("SCORE") && column.ActualWidth >= 110), "Score column lost minimum width");
                if (screenshotDirectory != null) Render(window, Path.Combine(screenshotDirectory, $"wpf-{language}-{name}-normal.png"));
            }
            window.Width = 1000; window.Height = 640; Pump(); window.UpdateLayout();
        }
        Check(new UiPreferences(Path.Combine(temporary, "preferences.json")).Data.Language == "hu", "Selector did not persist HU");
        Check(vm.Notifications.Items.Count == 0, "Opening/refreshing pages notified");
        Check(File.ReadAllBytes(configPath).SequenceEqual(before), "Navigation/language handling mutated policy");
        vm.Notifications.Observe("fixture", true, NotificationCategory.EngineDns, NotificationSeverity.Critical, "Engine unreachable", "HostsGuardian cannot reach the DNS Engine.", "Router");
        Check(vm.Notifications.HasCritical, "Critical state unavailable");
        vm.NotificationsOpen = true; Pump(); window.UpdateLayout();
        var panel = (FrameworkElement)window.FindName("NotificationPanel"); Check(panel.Visibility == Visibility.Visible, "Notification panel not visible");
        if (screenshotDirectory != null) Render(window, Path.Combine(screenshotDirectory, "wpf-hu-notifications.png"));
        vm.OpenNotification(vm.Notifications.Items[0]); Pump();
        Check(vm.IsRouterVisible && !vm.NotificationsOpen && vm.Notifications.UnreadCount == 0 && vm.Notifications.HasCritical, "Notification action changed/cleared critical policy state");
        Check(File.ReadAllBytes(configPath).SequenceEqual(before), "Notification handling mutated policy");
        window.Width = 1400; window.Height = 900; window.UpdateLayout();
        Check(panel.Visibility == Visibility.Collapsed, "Panel permanently steals workspace");
        Check(listener.Errors.Count == 0, "Binding errors: " + string.Join("\n", listener.Errors));
        window.Close(); PresentationTraceSources.DataBindingSource.Listeners.Remove(listener);
        Console.WriteLine("PASS actual EN/HU selector, navigation, compact layout, tooltips, notification actions and unchanged policy bytes");
        var structured = new ActivityEvent("WPF user action", "Policy", "Added domain: {0}", new[] { "fixture.invalid" }, Target: "fixture.invalid", Action: "Add", Outcome: "LocalDraftSaved");
        var read = ActivityEvent.Parse(structured.Serialize());
        Check(read?.Actor == null && read?.Target == "fixture.invalid" && read.Display.Contains("fixture.invalid"), "Audit metadata fabricated/lost identity or target");
        Check(ActivityEvent.Parse("Legacy diagnostic message") == null, "Legacy audit reclassified");
        Console.WriteLine("PASS structured local user events preserve nullable identity, target, outcome and legacy messages");
        var observed = new MainViewModel(configService, false, new AuditLogService(Path.Combine(temporary, "observed.log")));
        var presentation = (EngineStatusPresentation)typeof(MainViewModel).GetField("_engineStatus", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(observed)!;
        void Result(ConnectionResult result)
        {
            presentation.Complete(result);
            typeof(MainViewModel).GetMethod("ObserveConnection", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(observed, new object[] { result });
        }
        Result(new(ConnectionState.Unreachable, "Engine unreachable"));
        observed.RefreshCommand.Execute(null);
        Result(new(ConnectionState.Unreachable, "Engine unreachable"));
        Check(observed.Notifications.Items.Count == 1 && observed.Notifications.HasCritical, "Real failure wiring/refresh deduplication failed");
        Result(new(ConnectionState.Authenticated, "Engine online; authenticated", new DnsServiceStatus
        { UdpListening = true, TcpListening = true, ManagementListening = true, RuntimeState = "Running" }));
        Check(!observed.Notifications.HasCritical && observed.Notifications.Items[0].Resolved, "Fresh successful connection did not resolve unreachable");
        Result(new(ConnectionState.Authenticated, "Engine online; authenticated", new DnsServiceStatus
        { UdpListening = true, TcpListening = true, LastUpstreamOutcome = "Response", LastUpstreamSuccessUtc = DateTimeOffset.UtcNow, LastUpstreamRequestUsedFallback = true }));
        Check(observed.Notifications.Items.Any(i => i.Key == "upstream" && !i.Resolved), "Observed fallback did not warn");
        Result(new(ConnectionState.Authenticated, "Engine online; authenticated", new DnsServiceStatus { UdpListening = true, TcpListening = true }));
        Check(observed.Notifications.Items.Any(i => i.Key == "upstream" && !i.Resolved), "Unknown upstream observation fabricated recovery");
        observed.Dispose();
        Check(File.ReadAllBytes(configPath).SequenceEqual(before), "Real observation wiring mutated policy");
        Console.WriteLine("PASS actual connection observation wiring, passive refresh, confirmed recovery and unknown upstream preservation");
        var rejected = new MainViewModel(configService, false, new AuditLogService(Path.Combine(temporary, "reject.log")));
        rejected.Devices.Add(new DeviceVm(new NetworkDevice { Ip = "192.0.2.10", Mac = "02:00:00:00:00:01" }, "Fixture laptop", false) { DeviceId = deviceId });
        rejected.SelectedDevice = rejected.Devices[0];
        File.Move(configPath, configPath + ".saved"); Directory.CreateDirectory(configPath);
        var rejectedRow = rejected.DeviceDomainRules.Single(); rejectedRow.State = DeviceDomainRuleState.Block;
        Check(rejectedRow.State == DeviceDomainRuleState.Inherit && rejected.HasError && File.ReadAllBytes(configPath + ".saved").SequenceEqual(before), "Real rejected config save did not roll back");
        Check(rejected.Notifications.Items.Single().Title == L.T("Draft could not be saved"), "Local draft failure misrepresented Engine confirmation");
        rejected.Dispose();
        Console.WriteLine("PASS real rejected device rule persistence retains prior selection and source policy bytes");
        L.Instance.ChangeLanguage("en", false);
        var blockedPreferencePath = Path.Combine(temporary, "blocked-preferences"); Directory.CreateDirectory(blockedPreferencePath);
        UiPreferences.Use(new UiPreferences(blockedPreferencePath));
        rejected.SelectedLanguage = "hu";
        Check(rejected.SelectedLanguage == "en" && rejected.HasError, "Failed preference save pretended a language switch succeeded");
        Console.WriteLine("PASS failed language persistence retains the prior language and reports the error");
    }
    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        { var child = VisualTreeHelper.GetChild(parent, i); yield return child; foreach (var descendant in Descendants(child)) yield return descendant; }
    }
    private static void Render(Window window, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path); encoder.Save(stream);
    }
}
