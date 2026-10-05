using L = HostsGuardian.Wpf.Localization.LocalizationService;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.Wpf;
public sealed class EngineConnectionWindow : Window
{
    private readonly AppConfig _config;
    private readonly ConfigService _service;
    private readonly ICredentialStore _store = new ProtectedCredentialStore();
    private readonly TextBox _address = new(), _port = new();
    private readonly PasswordBox _token = new();
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap }, _credential = new(), _trust = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _fingerprint = new() { TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas"), FontSize = 12 };
    private static readonly Brush Normal = Brush("#E6FFF0"), Muted = Brush("#A3B5AC"), Success = Brush("#00FF88"), Warning = Brush("#FFD166"), Error = Brush("#FF8585");
    private static Brush Brush(string color) => (Brush)new BrushConverter().ConvertFromString(color)!;
    private string _certificate;
    private bool _replace, _clear, _endpointChanged;
    private int _generation;
    public EngineConnectionWindow(AppConfig config, ConfigService service)
    {
        _config = config; _service = service; _certificate = config.DnsEngine.TrustedCertificate;
        Title = L.T("DNS Engine connection"); ToolTipService.SetInitialShowDelay(this, 2500); ToolTipService.SetBetweenShowDelay(this, 0); Width = 620; Height = 740; MinWidth = 540; MinHeight = 560; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Brush("#050A08"); Foreground = Normal; FontFamily = new FontFamily("Segoe UI"); FontSize = 13;
        Resources = new ResourceDictionary { Source = new Uri("/HostsGuardian.Wpf;component/Styles/MatrixStyles.xaml", UriKind.Relative) };
        var layout = new DockPanel { Margin = new Thickness(16) }; Content = layout;
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0,12,0,0) };
        DockPanel.SetDock(actions, Dock.Bottom); layout.Children.Add(actions);
        var panel = new StackPanel(); layout.Children.Add(new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        panel.Children.Add(new TextBlock { Text = L.T("DNS ENGINE CONNECTION"), Foreground = Success, FontSize = 18, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0,0,0,4) });
        panel.Children.Add(new TextBlock { Text = L.T("Configure management access. Filtering policy stays separate."), Foreground = Muted, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,12) });
        var endpoint = Section(panel,L.T("ENGINE ENDPOINT"));
        var security = Section(panel,L.T("SECURITY"));
        var connection = Section(panel,L.T("CONNECTION"));
        _address.Text = config.DnsEngine.Address;
        if (_address.Text == "" && Uri.TryCreate(config.DnsEngine.BaseUrl, UriKind.Absolute, out var old)) _address.Text = old.Host;
        _port.Text = config.DnsEngine.ManagementPort.ToString();
        endpoint.Children.Add(new TextBlock { Text = L.T("Engine address"), Margin = new Thickness(0,0,0,4) }); endpoint.Children.Add(_address);
        endpoint.Children.Add(new TextBlock { Text = L.T("Management port"), Margin = new Thickness(0,8,0,4) }); endpoint.Children.Add(_port);
        endpoint.Children.Add(new TextBlock { Text = L.T("HTTPS only · default management port 3000"), Foreground = Success, Margin = new Thickness(0,8,0,0) });
        RefreshCredential();
        security.Children.Add(_credential);
        AddButton(security, L.T("Replace credential"), () => { _replace = true; _clear = false; _token.IsEnabled = true; _token.Clear(); SetCredential(L.T("Replacement pending — enter an already provisioned credential"), Warning); });
        _token.IsEnabled = false; _token.Margin = new Thickness(0,8,0,0); security.Children.Add(_token);
        security.Children.Add(new TextBlock { Text = L.T("Masked input · stored credentials are never redisplayed"), Foreground = Muted, FontSize = 12, Margin = new Thickness(0,4,0,0) });
        AddButton(security, L.T("Remove local credential on SAVE"), () => { _clear = true; _replace = false; _token.Clear(); _token.IsEnabled = false; SetCredential(L.T("Local removal pending — does not revoke the Engine credential"), Warning); });
        _trust.Margin = new Thickness(0,10,0,4); security.Children.Add(_trust); security.Children.Add(_fingerprint); RefreshTrust();
        AddButton(security, L.T("Enroll server certificate…"), Enroll);
        if (config.DnsEngine.LegacyCredentialPresent)
            AddButton(security, L.T("Explicitly migrate existing plaintext credential"), () =>
            {
                try { _service.MigrateCredential(_config, _store); RefreshCredential(); SetStatus(L.T("Credential migrated — rotate old copies separately"), Success); }
                catch { SetStatus(L.T("Migration failed. Original plaintext configuration is retained; incompatible tokens require explicit local replacement."), Error); }
            });
        SetStatus(L.T("Not tested — testing does not save settings or change policy"), Muted);
        connection.Children.Add(_status);
        AddButton(connection, L.T("TEST CONNECTION"), async () =>
        {
            var generation = ++_generation;
            SetStatus(L.T("Testing — current connection unknown (read-only)"), Warning);
            try
            {
                if (_replace && ManagementSecurity.ParseToken(_token.Password) == null) { SetStatus(L.T("Credential unavailable: enter a valid provisioned credential"), Error); return; }
                var draft = Draft();
                if (_clear || (_endpointChanged && !_replace)) { SetStatus(L.T("Credential unavailable: enter a credential for this endpoint"), Error); return; }
                var result = await new DnsEngineService(credentials: _store).TestConnectionAsync(draft);
                if (generation != _generation) return;
                SetStatus(L.F("{0}: {1} (observed {2:HH:mm:ss} UTC)", L.T(result.State.ToString()), L.T(result.Message), DateTimeOffset.UtcNow), result.Ok ? Success : result.State == ConnectionState.CredentialUnavailable ? Warning : Error);
                if (result.Transport != null) _status.Text += L.F("\nDNS UDP: {0} :{1}\nDNS TCP: {2}\nEngine: {3}; filtering: {4}\nPolicy revision: {5}; synchronization: unconfirmed (test is read-only).", (result.Transport.UdpListening ? L.T("LISTENING") : L.T("STOPPED")), result.Transport.DnsPort, (result.Transport.TcpListening ? L.T("LISTENING") : L.T("STOPPED")), result.Transport.RuntimeState, (result.Transport.FilteringEnabled ? L.T("ENABLED") : result.Transport.EmergencySafeMode ? L.T("SAFE MODE BYPASS") : L.T("DISABLED")), result.Transport.PolicyRevision);
            }
            catch { if (generation == _generation) SetStatus(L.T("Invalid connection settings"), Error); }
        });
        AddButton(actions, L.T("SAVE"), Save);
        AddButton(actions, L.T("Cancel"), Close);
        _address.TextChanged += (_, _) => { _endpointChanged = true; _generation++; SetStatus(L.T("Settings changed — connection unknown; test again"), Warning); };
        _port.TextChanged += (_, _) => { _endpointChanged = true; _generation++; SetStatus(L.T("Settings changed — connection unknown; test again"), Warning); };
        _token.PasswordChanged += (_, _) => { _generation++; SetStatus(L.T("Credential input changed — connection unknown; test again"), Warning); };
        Closed += (_, _) => { _generation++; _token.Clear(); };
    }
    private static StackPanel Section(Panel parent, string title)
    {
        var contents = new StackPanel { Margin = new Thickness(10) };
        contents.Children.Add(new TextBlock { Text = title, Foreground = Success, FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0,0,0,10) });
        parent.Children.Add(new Border { Background = Brush("#0B1510"), BorderBrush = Brush("#244A37"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Margin = new Thickness(0,0,0,10), Child = contents });
        return contents;
    }
    private void SetStatus(string message, Brush color) { _status.Text = message; _status.Foreground = color; }
    private void SetCredential(string message, Brush color) { _credential.Text = message; _credential.Foreground = color; }
    private void RefreshCredential()
    {
        if (_config.DnsEngine.LegacyCredentialPresent) { SetCredential(L.T("Warning: legacy plaintext credential — explicit migration required"), Warning); return; }
        if (string.IsNullOrEmpty(_config.DnsEngine.CredentialId)) { SetCredential(L.T("Credential: not configured"), Muted); return; }
        if (_store.Read(_config.DnsEngine.CredentialId) == null) { SetCredential(L.T("Credential: unavailable / protected storage error"), Error); return; }
        SetCredential(L.T("Credential: stored"), Success);
    }
    private void RefreshTrust()
    {
        _fingerprint.Text = ""; _fingerprint.Foreground = Muted; _fingerprint.Visibility = Visibility.Collapsed;
        if (string.IsNullOrEmpty(_certificate)) { _trust.Text = L.T("Server certificate: not enrolled"); _trust.Foreground = Muted; return; }
        try
        {
            using var cert = new X509Certificate2(Convert.FromBase64String(_certificate));
            var valid = ManagementSecurity.ValidateCertificate(cert, _certificate, System.Net.Security.SslPolicyErrors.None);
            _trust.Text = valid ? L.T("Server certificate: enrolled — explicit trust") : L.T("Server certificate: invalid / expired / incompatible");
            _trust.Foreground = valid ? Success : Error;
            _fingerprint.Visibility = Visibility.Visible;
            _fingerprint.Text = L.F("SHA-256\n{0}\nValid until {1:u}\nEnrollment is not a live connection check. Verify identity independently.", Convert.ToHexString(SHA256.HashData(cert.RawData)), cert.NotAfter);
        }
        catch { _trust.Text = L.T("Server certificate: unavailable / invalid enrollment data"); _trust.Foreground = Error; }
    }
    private static void AddButton(Panel panel, string label, Action action)
    { var button = new Button { Content = label, Margin = new Thickness(0,6,8,0) }; button.Click += (_, _) => action(); panel.Children.Add(button); }
    private DnsEngineConfig Draft()
    {
        var cfg = new DnsEngineConfig { Enabled = true, Address = _address.Text.Trim(), ManagementPort = int.Parse(_port.Text),
            TrustedCertificate = _certificate, CredentialId = _config.DnsEngine.CredentialId, ApiToken = _replace ? _token.Password : "" };
        cfg.BaseUrl = ManagementSecurity.Endpoint(cfg).ToString(); return cfg;
    }
    private void Enroll()
    {
        var picker = new Microsoft.Win32.OpenFileDialog { Filter = L.T("Public certificate (*.cer;*.pem)|*.cer;*.pem") };
        if (picker.ShowDialog(this) != true) return;
        try
        {
            using var cert = new X509Certificate2(picker.FileName);
            if (cert.HasPrivateKey) { SetStatus(L.T("Select a public certificate only"), Error); return; }
            var fingerprint = Convert.ToHexString(SHA256.HashData(cert.RawData));
            if (!HostsGuardian.Wpf.Services.LocalizedDialogs.Confirm(this, L.F("Verify this SHA-256 fingerprint independently on the Linux/HostsGuardian Engine host before enrollment:\n{0}\nValid until {1:u}\nEnroll this server identity?", fingerprint, cert.NotAfter), L.T("Explicit certificate trust"))) return;
            _certificate = Convert.ToBase64String(cert.RawData); RefreshTrust(); _generation++; SetStatus(L.T("Trust draft changed — connection unknown; test again"), Warning);
        }
        catch { SetStatus(L.T("Certificate file could not be read"), Error); }
    }
    private void Save()
    {
        var previous = _config.DnsEngine;
        try
        {
            if (previous.LegacyCredentialPresent && !_replace) { SetStatus(L.T("Migrate the legacy credential or explicitly replace it before saving"), Error); return; }
            var draft = Draft();
            if (_endpointChanged && !_replace && !_clear) { SetStatus(L.T("Explicitly replace or remove the credential when changing endpoints"), Error); return; }
            if (previous.LegacyCredentialPresent)
            {
                if (!HostsGuardian.Wpf.Services.LocalizedDialogs.Confirm(this, L.T("Protect the entered replacement credential and remove the legacy plaintext from normal configuration? Original configuration remains intact if protection fails. This does not rotate the Engine token."), L.T("Explicit legacy replacement"))) return;
                var migrationConfig = JsonSerializer.Deserialize<AppConfig>(JsonSerializer.Serialize(_config))!;
                migrationConfig.DnsEngine = draft;
                _service.MigrateCredential(migrationConfig, _store, draft.ApiToken);
                draft.ApiToken = ""; _config.DnsEngine = draft; _token.Clear(); Close(); return;
            }
            if (_replace)
            {
                var id = Guid.NewGuid().ToString("N"); _store.Write(id, draft.ApiToken);
                if (_store.Read(id) != draft.ApiToken) throw new InvalidOperationException();
                draft.CredentialId = id;
            }
            if (_clear) draft.CredentialId = "";
            draft.ApiToken = ""; _config.DnsEngine = draft;
            try { _service.Save(_config); } catch { _config.DnsEngine = previous; throw; }
            if ((_clear || _replace) && previous.CredentialId != "")
            { try { _store.Delete(previous.CredentialId); } catch { SetStatus(L.T("Saved; previous local credential cleanup failed"), Error); _token.Clear(); return; } }
            _token.Clear(); Close();
        }
        catch { SetStatus(L.T("Save failed; settings were not confirmed. Check credential format and protected storage."), Error); }
    }
}
