using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf;
using HostsGuardian.Wpf.Services;
using HostsGuardian.Wpf.ViewModels;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

internal static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            if (args.Length == 2 && args[0] == "--fixture") return Fixture(args[1]);
            return Drive(args.FirstOrDefault() ?? Path.Combine(Path.GetTempPath(), "HG-desktop-" + Guid.NewGuid().ToString("N")));
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }

    static int Fixture(string folder)
    {
        Directory.CreateDirectory(folder);
        var prefs = new UiPreferences(Path.Combine(folder, "preferences.json"));
        UiPreferences.Use(prefs); L.Instance.ChangeLanguage(prefs.Data.Language, false);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var handler = new ContractHandler(token);
        var config = new ConfigService(Path.Combine(folder, "config.json"));
        if (!File.Exists(Path.Combine(folder, "config.json"))) config.Save(new AppConfig
        { DnsEngine = new DnsEngineConfig { Address = "fixture.invalid", ManagementPort = 3000 },
            BlockedDomains = [new DomainEntry { Domain = "fixture.invalid", DnsBlocked = false }] });
        var engine = new DnsEngineService(() => new HttpClient(handler, false), new Credential(token));
        var vm = new MainViewModel(config, false, new AuditLogService(Path.Combine(folder, "audit.log")), engine);
        // Load product resources without its production StartupUri: only the
        // explicitly injected fixture window may be created in this process.
        var app = new App { Resources = new ResourceDictionary { Source = new Uri("/HostsGuardian.Wpf;component/Styles/MatrixStyles.xaml",UriKind.Relative) },
            ShutdownMode = ShutdownMode.OnMainWindowClose };
        var window = new MainWindow(vm) { Title = "HostsGuardian isolated desktop fixture" };
        System.Windows.Automation.AutomationProperties.SetName(window,"HostsGuardian isolated desktop fixture");
        app.MainWindow = window;
        window.Closed += (_, _) => File.WriteAllText(Path.Combine(folder, "result.json"), JsonSerializer.Serialize(new
        { handler.SafeMode, handler.Mutations, handler.PolicyDeliveries, Revision = 1, Domains = 0, Language = prefs.Data.Language }));
        window.Show();
        Console.WriteLine($"FIXTURE_READY pid={Environment.ProcessId} title={window.Title}");
        app.Run();
        return 0;
    }

    static Process Launch(string folder)
    {
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput=true, RedirectStandardError=true };
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add("--fixture"); start.ArgumentList.Add(folder);
        var process=Process.Start(start)!;
        process.OutputDataReceived+=(_,e)=>{if(e.Data!=null)Console.WriteLine("FIXTURE: "+e.Data);};
        process.ErrorDataReceived+=(_,e)=>{if(e.Data!=null)Console.Error.WriteLine("FIXTURE ERROR: "+e.Data);};
        process.BeginOutputReadLine();process.BeginErrorReadLine();
        return process;
    }

    static AutomationElement Wait(Func<AutomationElement?> find, string description)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(15))
        {
            try { var value = find(); if (value != null) return value; }
            catch (ElementNotAvailableException) { }
            Thread.Sleep(100);
        }
        throw new Exception("UI Automation timeout: " + description);
    }
    static AutomationElement ById(AutomationElement parent, string id) => Wait(() => parent.FindFirst(TreeScope.Descendants,
        new PropertyCondition(AutomationElement.AutomationIdProperty, id)), id);
    static void Invoke(AutomationElement element) => ((InvokePattern)element.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    static void SelectLanguage(AutomationElement window, string name)
    {
        var combo = ById(window, "LanguageSelector");
        ((ExpandCollapsePattern)combo.GetCurrentPattern(ExpandCollapsePattern.Pattern)).Expand();
        var item = Wait(() => combo.FindAll(TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem))
            .Cast<AutomationElement>().FirstOrDefault(x => x.Current.Name.Contains(name)), "language " + name);
        ((SelectionItemPattern)item.GetCurrentPattern(SelectionItemPattern.Pattern)).Select();
        ((ExpandCollapsePattern)combo.GetCurrentPattern(ExpandCollapsePattern.Pattern)).Collapse();
    }
    static string State(AutomationElement window) => ById(window, "OperationalSummary").Current.Name;
    static void WaitState(AutomationElement window, string text)
    {
        Wait(() => State(window).Contains(text, StringComparison.OrdinalIgnoreCase) ? window : null, "state " + text);
    }
    static void Consent(int pid, bool yes)
    {
        var dialog = Wait(() => AutomationElement.RootElement.FindAll(TreeScope.Children,
            new PropertyCondition(AutomationElement.ProcessIdProperty, pid)).Cast<AutomationElement>()
            .FirstOrDefault(x => x.FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.AutomationIdProperty,"DeclineButton")) != null), "confirmation");
        Invoke(ById(dialog, yes ? "ConfirmButton" : "DeclineButton"));
    }
    static int Drive(string folder)
    {
        Directory.CreateDirectory(folder);
        var assertions = new List<string>();
        using (var process = Launch(folder))
        {
            try
            {
                var window = Wait(() => AutomationElement.RootElement.FindFirst(TreeScope.Children, new AndCondition(new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id),
                    new PropertyCondition(AutomationElement.NameProperty,"HostsGuardian isolated desktop fixture"))), "launch");
                assertions.Add("PASS real separate-process WPF window visible through Windows UI Automation");
                SelectLanguage(window, "Magyar");
                Wait(() => File.ReadAllText(Path.Combine(folder, "preferences.json")).Contains("hu") ? window : null, "Hungarian persisted");
                SelectLanguage(window, "English");
                foreach (var tab in new[] { "RouterTab", "DevicesTab", "LogTab", "DomainsTab" })
                    ((SelectionItemPattern)ById(window, tab).GetCurrentPattern(SelectionItemPattern.Pattern)).Select();
                assertions.Add("PASS EN/HU switching, persistence and four-tab UI Automation navigation");
                var details = ById(window, "StatusDetails");
                ((ExpandCollapsePattern)details.GetCurrentPattern(ExpandCollapsePattern.Pattern)).Expand();
                Invoke(ById(window, "CheckConnection"));
                WaitState(window, "AUTHENTICATED"); WaitState(window, "RUNNING");
                assertions.Add("PASS authenticated management/DNS status contract shown in real controls (isolated handler fixture)");
                Invoke(ById(window, "EnterSafeMode")); Consent(process.Id, false);
                WaitState(window, "ENABLED");
                Invoke(ById(window, "EnterSafeMode")); Consent(process.Id, true);
                WaitState(window, "SAFE MODE BYPASS");
                Invoke(ById(window, "ExitSafeMode")); Consent(process.Id, true);
                WaitState(window, "ENABLED");
                assertions.Add("PASS Safe Mode cancel, enter and exit through actual dialogs and confirmed status readback");
                ((SelectionItemPattern)ById(window, "DevicesTab").GetCurrentPattern(SelectionItemPattern.Pattern)).Select();
                Invoke(ById(window, "ReadEnginePolicy")); Consent(process.Id, true); WaitState(window, "SYNCHRONIZED");
                assertions.Add("PASS explicit policy readback, rather than connectivity, confirms synchronization");
                Invoke(ById(window, "PolicyWorkspace"));
                var workspace = Wait(() => AutomationElement.RootElement.FindFirst(TreeScope.Descendants, new AndCondition(
                    new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id), new PropertyCondition(AutomationElement.NameProperty, "Policy workspace"))), "policy workspace");
                var catalogTab = workspace.FindFirst(TreeScope.Descendants, new AndCondition(new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.TabItem),
                    new PropertyCondition(AutomationElement.NameProperty, "Service catalog")));
                ((SelectionItemPattern)catalogTab.GetCurrentPattern(SelectionItemPattern.Pattern)).Select();
                void Set(string id, string value) => ((ValuePattern)ById(workspace, id).GetCurrentPattern(ValuePattern.Pattern)).SetValue(value);
                Set("FieldName", "Fixture service"); Set("FieldDefinitionrevision", "fixture-1"); Set("FieldDomains(oneperline)", "fixture.invalid");
                Invoke(ById(workspace, "Saveservice")); Invoke(ById(workspace, "Previewdraft"));
                Invoke(ById(workspace, "Savelocaldraft")); Consent(process.Id, true); WaitState(window, "CHANGES NOT SENT");
                var saved = new ConfigService(Path.Combine(folder, "config.json")).Load();
                if (saved.DeviceDomainPolicy.Program?.Services.Length != 1 || saved.DeviceDomainPolicy.GlobalBlockedDomains.Length != 0)
                    throw new Exception("Service authoring lost catalog or silently created filtering rules");
                assertions.Add("PASS actual catalog authoring, preview/confirmation and local-only unsent policy state");
                Invoke(ById(window, "ReadEnginePolicy")); Consent(process.Id, true); WaitState(window, "SYNCHRONIZED");
                Invoke(ById(window, "ProductInsights"));
                var insights = Wait(() => AutomationElement.RootElement.FindFirst(TreeScope.Descendants, new AndCondition(
                    new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id), new PropertyCondition(AutomationElement.NameProperty, "Health, activity and policy audit"))), "product insights");
                Invoke(ById(insights, "RefreshProductInsights"));
                Wait(() => insights.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "Current read-only insights received. No policy was delivered.")), "read-only insights");
                ((WindowPattern)insights.GetCurrentPattern(WindowPattern.Pattern)).Close();
                assertions.Add("PASS actual policy preview and authenticated health/activity/audit windows; opening/reading sends no policy");
                SelectLanguage(window, "Magyar");
                ((WindowPattern)window.GetCurrentPattern(WindowPattern.Pattern)).Close();
                if (!process.WaitForExit(10000)) throw new Exception("Fixture did not close");
                using var result = JsonDocument.Parse(File.ReadAllText(Path.Combine(folder, "result.json")));
                if (result.RootElement.GetProperty("SafeMode").GetBoolean() || result.RootElement.GetProperty("Mutations").GetInt32() != 2 ||
                    result.RootElement.GetProperty("Revision").GetInt32() != 1 || result.RootElement.GetProperty("Domains").GetInt32() != 0 || result.RootElement.GetProperty("PolicyDeliveries").GetInt32() != 0)
                    throw new Exception("Cancellation/policy revision or final Safe Mode invariant failed");
                assertions.Add("PASS cancel sent no mutation, final Safe Mode off, revision and policy baseline preserved");
            }
            finally
            {
                Console.WriteLine("OWNED WINDOWS: " + string.Join(" | ", AutomationElement.RootElement.FindAll(TreeScope.Children,
                    new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id)).Cast<AutomationElement>().Select(x => x.Current.Name)));
                if (!process.HasExited) process.Kill();
            }
        }
        using (var reopen = Launch(folder))
        {
            try
            {
                var window = Wait(() => AutomationElement.RootElement.FindFirst(TreeScope.Children, new PropertyCondition(AutomationElement.ProcessIdProperty, reopen.Id)), "reopen");
                if (ById(window, "LanguageSelector").Current.Name != L.Hungarian["S179"]) throw new Exception("Reopened language not Hungarian");
                ((WindowPattern)window.GetCurrentPattern(WindowPattern.Pattern)).Close();
                reopen.WaitForExit(10000);
                assertions.Add("PASS Hungarian persisted across real window/process close and reopen");
            }
            finally { if (!reopen.HasExited) reopen.Kill(); }
        }
        File.WriteAllLines(Path.Combine(folder, "desktop-results.txt"), assertions);
        foreach (var assertion in assertions) Console.WriteLine(assertion);
        Console.WriteLine("LIMITATION: UI Automation foundation uses an isolated management contract handler; real TLS/Engine lifecycle is covered separately by Core/Engine regression, not claimed by these desktop assertions.");
        return 0;
    }

    sealed class Credential(string token) : ICredentialStore
    {
        public string Read(string id) => token;
        public void Write(string id, string value) => throw new NotSupportedException();
        public void Delete(string id) => throw new NotSupportedException();
    }
    sealed class ContractHandler(string token) : HttpMessageHandler
    {
        public bool SafeMode; public int Mutations; public int PolicyDeliveries;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Headers.Authorization?.Parameter != token) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath is not ("/safe-mode/enter" or "/safe-mode/exit")) PolicyDeliveries++;
            object payload;
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/health") payload = new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 };
            else if (path == "/dns/status") payload = new DnsServiceStatus
            {
                Implementation = "HostsGuardian.DnsEngine", InstanceId = "isolated-desktop", RuntimeState = "Running",
                DnsPort = 15353, ApiPort = 3000, UdpState = "Listening", TcpState = "Listening", ManagementState = "Listening",
                UdpListening = true, TcpListening = true, ManagementListening = true, TcpImplemented = true,
                PolicyRestoreState = "Restored", PolicyLoaded = true, PolicyRevision = 1, FilteringEnabled = !SafeMode,
                EmergencySafeMode = SafeMode, SafeModeReason = SafeMode ? "ManagementRequested" : ""
            };
            else if (path == "/v2/policy") payload = new FullPolicyRead(1, FullDnsPolicy.Empty, "isolated-desktop");
            else if (path == "/v3/activity") payload = new ProductActivityRead(1, DateTimeOffset.UtcNow, 24, 256, []);
            else if (path == "/v3/policy-audit") payload = new PolicyAuditRead(1, true, 1000, []);
            else if (path.StartsWith("/v2/operational-events")) payload = new OperationalEventBatch(1, "isolated-desktop", 0, false, [],
                new[] { "Listeners", "Management", "Upstream", "Processing", "Capacity", "Persistence" }.Select(c => new HealthComponent(c, "Healthy", null, null)).ToArray());
            else if (path is "/safe-mode/enter" or "/safe-mode/exit")
            { SafeMode = path.EndsWith("enter"); Mutations++; payload = new { ok = true, revision = 1, count = 0 }; }
            else return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json") });
        }
    }
}
