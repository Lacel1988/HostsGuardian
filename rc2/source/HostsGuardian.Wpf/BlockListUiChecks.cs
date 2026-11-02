using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
    internal async Task RunBlockListRestartCheck(string fixtureFile, string output)
    {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(fixtureFile)); var root = doc.RootElement;
        var config = root.GetProperty("configuration").Deserialize<DesignPrototype.Engine.LiveConfiguration>()!;
        if (!System.Net.IPAddress.IsLoopback(System.Net.IPAddress.Parse(new Uri(config.Origin).Host))) throw new InvalidOperationException("Loopback fixture only");
        ConnectionProvider = _ => Task.FromResult(new LabConnection(config, root.GetProperty("credentialDirectory").GetString()!));
        SetReducedMotion(true); await LoginToEngine("admin", root.GetProperty("password").GetString()!);
        var deadline = DateTime.UtcNow.AddSeconds(10); while ((!DashboardVisible || StartupVisible) && DateTime.UtcNow < deadline) await Task.Delay(50);
        Navigate("Domainek és policy");
        while (!Descendants(Surface).OfType<ToggleButton>().Any(b => AutomationProperties.GetAutomationId(b) == "ToggleBlock_saved-off.invalid") && DateTime.UtcNow < deadline) await Task.Delay(50);
        var row = Descendants(Surface).OfType<ToggleButton>().Single(b => AutomationProperties.GetAutomationId(b) == "ToggleBlock_saved-off.invalid");
        if (row.IsChecked != false || !row.IsEnabled) throw new InvalidOperationException("Disabled entry lost after process restart");
        Directory.CreateDirectory(output); File.WriteAllText(Path.Combine(output, "wpf-process-restart.json"), JsonSerializer.Serialize(new { pass = true, source = "New WPF process; same isolated HTTPS Engine", disabledEntryRetained = true }));
    }
    internal async Task RunBlockListUiChecks(string output, Action<string, bool> check)
    {
        T? Find<T>(string id) where T : FrameworkElement => Descendants(Surface).OfType<T>().FirstOrDefault(b => AutomationProperties.GetAutomationId(b) == id);
        async Task Wait(Func<bool> done, int seconds = 10) { var until = DateTime.UtcNow.AddSeconds(seconds); while (!done() && DateTime.UtcNow < until) await Task.Delay(50); if (!done()) throw new InvalidOperationException("Block list UI timeout"); }
        async Task Fresh() => await Wait(() => Find<Button>("AddBlockDomain")?.IsEnabled == true && Find<TextBlock>("BlockListFeedback")?.Text.StartsWith("Engine visszaigazolva") == true);
        async Task<JsonElement> Policy() => (await userSession!.Call("/v2/policy"))!.Value;
        async Task Add(string domain) { Find<TextBox>("BlockListDomain")!.Text = domain; Find<Button>("AddBlockDomain")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); await Wait(() => Find<ToggleButton>("ToggleBlock_" + domain)?.IsEnabled == true); }
        bool Text(string value) => Descendants(Surface).OfType<TextBlock>().Any(t => t.Text.Contains(value));
        void Capture(string file)
        {
            UpdateLayout();
            var image = new RenderTargetBitmap((int)Math.Ceiling(ActualWidth), (int)Math.Ceiling(ActualHeight), 96, 96, PixelFormats.Pbgra32); image.Render(this);
            var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(image)); using var stream = File.Create(Path.Combine(output, file)); png.Save(stream);
        }
        Navigate("Domainek és policy"); await Fresh();
        check("Block list technical state selector removed", !Descendants(Surface).OfType<ComboBox>().Any(c => c.Items.Cast<object>().Any(i => i?.ToString() == "Inherit")));
        await Add("list.invalid");
        check("WPF add sends actual global policy", (await Policy()).GetProperty("policy").GetProperty("globalBlockedDomains").EnumerateArray().Any(e => e.GetString() == "list.invalid"));
        var toggle = Find<ToggleButton>("ToggleBlock_list.invalid")!; toggle.Focus(); toggle.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        await Wait(() => Find<ToggleButton>("ToggleBlock_list.invalid") is { IsChecked: false, IsEnabled: true });
        check("WPF focus restored to recreated switch", Find<ToggleButton>("ToggleBlock_list.invalid")?.IsKeyboardFocused == true);
        check("WPF disabled domain retained and green from readback", Find<ToggleButton>("ToggleBlock_list.invalid") != null && Text("Nincs érvényes blokkolás") && (await Policy()).GetProperty("policy").GetProperty("savedDomains").EnumerateArray().Any(e => e.GetProperty("domain").GetString() == "list.invalid"));
        Navigate("Áttekintés"); Navigate("Domainek és policy"); await Fresh();
        check("WPF page reload restores disabled engine entry", Find<ToggleButton>("ToggleBlock_list.invalid")?.IsChecked == false);
        Find<ToggleButton>("ToggleBlock_list.invalid")!.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        await Wait(() => Find<ToggleButton>("ToggleBlock_list.invalid") is { IsChecked: true, IsEnabled: true });
        check("WPF one-click re-enable", (await Policy()).GetProperty("policy").GetProperty("globalBlockedDomains").EnumerateArray().Any(e => e.GetString() == "list.invalid"));
        await Add("saved-off.invalid"); Find<ToggleButton>("ToggleBlock_saved-off.invalid")!.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        await Wait(() => Find<ToggleButton>("ToggleBlock_saved-off.invalid") is { IsChecked: false, IsEnabled: true });
        ChangeTheme(false); await Fresh(); Capture("block-list-dark.png");
        ChangeTheme(true); await Fresh(); Capture("block-list-light.png");
        var search = Find<TextBox>("BlockListSearch")!; search.Text = "saved-off";
        check("WPF search filters rows", Find<ToggleButton>("ToggleBlock_list.invalid") == null && Find<ToggleButton>("ToggleBlock_saved-off.invalid") != null); search.Text = "";
        Find<ComboBox>("BlockListScope")!.SelectedIndex = 1; await Fresh();
        check("WPF global inherited block is red while own switch off", Text("Globálisan tiltva") && Find<ToggleButton>("ToggleBlock_list.invalid")?.IsChecked == false);
        await Add("device-only.invalid");
        var p = (await Policy()).GetProperty("policy"); var first = p.GetProperty("devices")[0].GetProperty("deviceId").GetGuid();
        check("WPF device rule targets selected DeviceId", p.GetProperty("overrides").EnumerateArray().Any(r => r.GetProperty("domain").GetString() == "device-only.invalid" && r.GetProperty("deviceId").GetGuid() == first));
        check("WPF does not claim live device enforcement", Text("DNS-hatás: nem igazolt"));
        ChangeTheme(false); await Fresh(); Capture("block-list-device.png");
        Width = 1100; Height = 700; await Task.Delay(150); Capture("block-list-compact.png");
        check("WPF compact list controls fit client width", Find<ToggleButton>("ToggleBlock_device-only.invalid") is { ActualWidth: > 0 } button && button.TranslatePoint(new Point(button.ActualWidth, 0), this).X <= ActualWidth);
        Width = 1360; Height = 850;
        Find<Button>("DeleteBlock_device-only.invalid")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); await Task.Delay(50);
        Find<Button>("DeleteSavedDomain")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        await Wait(() => Find<ToggleButton>("ToggleBlock_device-only.invalid") == null && Find<Button>("AddBlockDomain")?.IsEnabled == true);
        check("WPF delete distinct from disable", !(await Policy()).GetProperty("policy").GetProperty("overrides").EnumerateArray().Any(r => r.GetProperty("domain").GetString() == "device-only.invalid"));
        // Advance the server revision without refreshing the UI, then exercise its stale write failure.
        var read = await Policy(); await userSession!.Call("/v1/access/global-rule", new { expectedInstanceId = read.GetProperty("instanceId").GetString(), expectedRevision = read.GetProperty("revision").GetInt64(), domain = "advance-ui.invalid", blocked = true });
        Find<ToggleButton>("ToggleBlock_list.invalid")!.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        await Wait(() => Text("Nem igazolt módosítás"));
        check("WPF stale write never shows false success and disables controls", Find<ToggleButton>("ToggleBlock_list.invalid")?.IsEnabled == false && Text("Állapot nem igazolt"));
        Find<Button>("RefreshBlockList")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); await Fresh();
        check("WPF refresh recovers authoritative state", Text("Globálisan tiltva"));
        Find<ToggleButton>("ToggleBlock_list.invalid")!.Focus();
        read = await Policy(); await userSession!.Call("/v1/access/global-rule", new { expectedInstanceId = read.GetProperty("instanceId").GetString(), expectedRevision = read.GetProperty("revision").GetInt64(), domain = "auto-ui.invalid", blocked = true });
        await Wait(() => Find<ToggleButton>("ToggleBlock_auto-ui.invalid") != null, 30);
        check("WPF automatic readback retains keyboard focus", Find<ToggleButton>("ToggleBlock_list.invalid")?.IsKeyboardFocused == true);
        var bindings = (await userSession!.Call("/v2/bindings"))!.Value;
        await userSession.Call("/v2/bindings/replace", new { expectedGeneration = bindings.GetProperty("generation").GetInt64(), observations = Array.Empty<object>() });
        Find<Button>("RefreshBlockList")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); await Fresh();
        check("WPF unvalidated device is neutral, never false green", Text("nincs validált eszközkötés") && !Text("Nincs érvényes blokkolás"));
        Capture("block-list-unidentified.png");
        var emptyBindings = (await userSession.Call("/v2/bindings"))!.Value;
        await userSession.Call("/v2/bindings/replace", new { expectedGeneration = emptyBindings.GetProperty("generation").GetInt64(), observations = bindings.GetProperty("observations") });
        // Restore UI test scope for subsequent RBAC checks.
        blockListScope = null; blockListSearch = "";
        Navigate("Áttekintés");
    }
}
