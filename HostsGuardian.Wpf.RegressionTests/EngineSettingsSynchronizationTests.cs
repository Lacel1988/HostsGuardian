using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf;
using HostsGuardian.Wpf.ViewModels;

internal static class EngineSettingsSynchronizationTests
{
    private const BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Instance;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static T Field<T>(MainViewModel vm, string name) => (T)typeof(MainViewModel).GetField(name, Private)!.GetValue(vm)!;
    private static Task Call(MainViewModel vm, string name, params object[] args) =>
        (Task)typeof(MainViewModel).GetMethod(name, Private)!.Invoke(vm, args)!;
    private static void Pump(Task task)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!task.IsCompleted && DateTime.UtcNow < deadline)
        { Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.Background); Thread.Sleep(1); }
        Check(task.IsCompleted, "Fixture request timed out"); task.GetAwaiter().GetResult();
    }
    public static void Run()
    {
        var directory = Path.Combine(Path.GetTempPath(), "hg-settings-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var store = new ConfigService(Path.Combine(directory, "config.json"));
        store.Save(new AppConfig { DnsEngine = new() { Enabled = true, BaseUrl = "https://old.fixture.invalid:3000", CredentialId = "fixture" } });
        var handler = new Handler();
        var vm = new MainViewModel(store, false, new AuditLogService(Path.Combine(directory, "audit.log")),
            new DnsEngineService(() => new HttpClient(handler, false), new Credentials()));
        var config = Field<AppConfig>(vm, "_config");
        var originalDraft = JsonSerializer.Serialize(new { config.DeviceDomainPolicy, config.BlockedDomains, config.DeviceRuleRestorePoints });

        // Exercise the actual settings Save callback; no credential replacement/enrollment.
        Check(new DnsEngineService(() => new HttpClient(handler, false), new Credentials()).TestConnectionAsync(config.DnsEngine).GetAwaiter().GetResult().Ok,
            "Settings test fixture failed");
        var before = JsonSerializer.Serialize(config.DnsEngine);
        var dialog = new EngineConnectionWindow(config, store);
        typeof(EngineConnectionWindow).GetMethod("Save", Private)!.Invoke(dialog, null);
        Check(dialog.SaveSucceeded, "Successful Save not reported");
        Pump(Call(vm, "CompleteEngineSettingsAsync", before, dialog.SaveSucceeded));
        var status = Field<EngineStatusPresentation>(vm, "_engineStatus");
        Check(status.EngineHost == "ONLINE" && status.Management == "AUTHENTICATED" && status.Current != null,
            "Save did not refresh main-window status");
        Check(handler.PolicyReads == 0 && JsonSerializer.Serialize(new { config.DeviceDomainPolicy, config.BlockedDomains, config.DeviceRuleRestorePoints }) == originalDraft, "Save imported policy or changed draft");
        Console.WriteLine("PASS settings Test/Save refreshes main status read-only without policy import");

        var baseline = new FullPolicyRead(7, FullDnsPolicy.Empty, "old.fixture.invalid");
        typeof(MainViewModel).GetField("_fullPolicyBaseline", Private)!.SetValue(vm, baseline);
        var confirmed = status.LastConfirmed;
        Pump(Call(vm, "CompleteEngineSettingsAsync", JsonSerializer.Serialize(config.DnsEngine), false));
        Check(ReferenceEquals(confirmed, status.LastConfirmed) && ReferenceEquals(baseline, Field<FullPolicyRead>(vm, "_fullPolicyBaseline")),
            "Unchanged Cancel reset status or baseline");
        Console.WriteLine("PASS unchanged Cancel preserves status and policy baseline");

        handler.DelayOld = true;
        var oldRequest = Call(vm, "RefreshConnectionAsync");
        before = JsonSerializer.Serialize(config.DnsEngine);
        config.DnsEngine = new() { Enabled = true, BaseUrl = "https://new.fixture.invalid:3000", CredentialId = "fixture" };
        Pump(Call(vm, "CompleteEngineSettingsAsync", before, true));
        Check(typeof(MainViewModel).GetField("_fullPolicyBaseline", Private)!.GetValue(vm) == null, "Endpoint retained old baseline");
        handler.Release.TrySetResult(true); Pump(oldRequest);
        Check(status.Current?.InstanceId == "new.fixture.invalid" && !Field<bool>(vm, "_engineRequestPending"), "Late old response overwrote new endpoint");
        Console.WriteLine("PASS endpoint change invalidates baseline and rejects delayed old status");

        vm.PushDnsCommand.Execute(null);
        Check(handler.Writes == 0 && status.EngineHost == "ONLINE" && vm.HasError, "Baseline-free send wrote policy or erased connectivity");
        Console.WriteLine("PASS baseline-free delivery stays blocked without erasing connectivity");

        handler.FailPolicy = true;
        var draftBeforeRead = JsonSerializer.Serialize(config);
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(10) };
        timer.Tick += (_, _) =>
        {
            var button = Application.Current.Windows.OfType<Window>().Select(w => w.Content).OfType<DockPanel>()
                .SelectMany(p => p.Children.OfType<StackPanel>()).SelectMany(p => p.Children.OfType<Button>()).FirstOrDefault(b => b.Name == "ConfirmButton");
            if (button != null) { timer.Stop(); button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); }
        };
        timer.Start(); vm.LoadFullPolicyCommand.Execute(null); timer.Stop();
        Check(handler.PolicyReads == 1 && status.EngineHost == "ONLINE" && vm.EnginePolicyReadbackText == HostsGuardian.Wpf.Localization.LocalizationService.T("Policy readback failed; connection status is separate"),
            "Policy read failure obscured successful connection or lacked separate message");
        Check(JsonSerializer.Serialize(config) == draftBeforeRead && handler.Writes == 0, "Failed read changed local draft or Engine policy");
        Console.WriteLine("PASS successful connection and policy-read failure are displayed separately");
        Console.WriteLine("PASS failed policy read preserves local draft and performs no policy writes");
        vm.Dispose();
    }
    private sealed class Handler : HttpMessageHandler
    {
        public int PolicyReads, Writes;
        public bool DelayOld, FailPolicy;
        public TaskCompletionSource<bool> Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/v2/policy") { PolicyReads++; if (FailPolicy) return new(HttpStatusCode.ServiceUnavailable); }
            if (request.Method != HttpMethod.Get) { Writes++; throw new Exception("Unexpected production mutation in fixture"); }
            if (path == "/dns/status" && request.RequestUri.Host == "old.fixture.invalid" && DelayOld) await Release.Task;
            object body = path switch
            {
                "/health" => new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 },
                "/dns/status" => new DnsServiceStatus { Implementation = "HostsGuardian.DnsEngine", InstanceId = request.RequestUri.Host,
                    DnsPort = 53, ApiPort = 3000, PolicyRevision = 7, PolicyLoaded = true, FilteringEnabled = true },
                _ => throw new Exception("Unexpected fixture endpoint " + path)
            };
            return new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(body, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })) };
        }
    }
    private sealed class Credentials : ICredentialStore
    {
        public string? Read(string id) => new('a', 64);
        public void Write(string id, string token) => throw new Exception("Credential write forbidden");
        public void Delete(string id) => throw new Exception("Credential deletion forbidden");
    }
}
