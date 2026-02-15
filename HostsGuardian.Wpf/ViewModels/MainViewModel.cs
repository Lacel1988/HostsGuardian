using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Infrastructure;
using HostsGuardian.Wpf.Services;

namespace HostsGuardian.Wpf.ViewModels
{
    public sealed class MainViewModel : ObservableObject
    {
        // Core services
        private readonly ConfigService _configService = new();
        private readonly HostsService _hostsService = new();
        private readonly AuditLogService _logService = new();
        private readonly StatusExportService _exportService = new();
        private readonly HostsGuardian.Core.Services.NetworkScanService _networkScan = new();

        // WPF services
        private readonly FileDialogService _fileDialog = new();
        private readonly DnsPanelService _dnsPanel = new();
        private readonly HostsGuardian.Wpf.Services.RouterDetectService _routerDetect = new();

        private AppConfig _config;

        // ===================== SPA PAGE SWITCH =====================
        public enum PageKind { Domains, Router, Dns }

        private PageKind _currentPage = PageKind.Domains;
        public PageKind CurrentPage
        {
            get => _currentPage;
            set
            {
                if (Set(ref _currentPage, value))
                {
                    OnPropertyChanged(nameof(IsDomainsPage));
                    OnPropertyChanged(nameof(IsRouterPage));
                    OnPropertyChanged(nameof(IsDnsPage));
                }
            }
        }

        public bool IsDomainsPage => CurrentPage == PageKind.Domains;
        public bool IsRouterPage => CurrentPage == PageKind.Router;
        public bool IsDnsPage => CurrentPage == PageKind.Dns;

        // ===================== DOMAIN BLOCKING =====================

        public ObservableCollection<DomainEntry> Domains { get; }

        private DomainEntry? _selectedDomain;
        public DomainEntry? SelectedDomain
        {
            get => _selectedDomain;
            set => Set(ref _selectedDomain, value);
        }

        private string _newDomain = "";
        public string NewDomain
        {
            get => _newDomain;
            set => Set(ref _newDomain, value);
        }

        private string _previewText = "";
        public string PreviewText
        {
            get => _previewText;
            set => Set(ref _previewText, value);
        }

        private bool _hostsBlockActive;
        public bool HostsBlockActive
        {
            get => _hostsBlockActive;
            set
            {
                if (Set(ref _hostsBlockActive, value))
                    StatusText = value ? "ACTIVE" : "INACTIVE";
            }
        }

        private string _statusText = "INACTIVE";
        public string StatusText
        {
            get => _statusText;
            set => Set(ref _statusText, value);
        }

        // ===================== ERROR =====================

        private string _lastError = "";
        public string LastError
        {
            get => _lastError;
            set
            {
                if (Set(ref _lastError, value))
                    OnPropertyChanged(nameof(HasError));
            }
        }

        public bool HasError => !string.IsNullOrWhiteSpace(LastError);

        // ===================== ACTIVITY =====================

        public ObservableCollection<string> ActivityLines { get; } = new();

        private bool _isPreviewOpen = true;
        public bool IsPreviewOpen
        {
            get => _isPreviewOpen;
            set => Set(ref _isPreviewOpen, value);
        }

        // ===================== DNS PANEL =====================

        private string _dnsSnapshot = "";
        public string DnsSnapshot
        {
            get => _dnsSnapshot;
            set => Set(ref _dnsSnapshot, value);
        }

        // ===================== ROUTER / DEVICES =====================

        private RouterDetectResult _router = RouterDetectResult.Empty();

        private string _routerSummaryLine1 = "Gateway: (unknown)";
        public string RouterSummaryLine1
        {
            get => _routerSummaryLine1;
            set => Set(ref _routerSummaryLine1, value);
        }

        private string _routerSummaryLine2 = "Adapter: (unknown)";
        public string RouterSummaryLine2
        {
            get => _routerSummaryLine2;
            set => Set(ref _routerSummaryLine2, value);
        }

        private string _routerSummaryLine3 = "Local IP: (unknown)";
        public string RouterSummaryLine3
        {
            get => _routerSummaryLine3;
            set => Set(ref _routerSummaryLine3, value);
        }

        private string _networkSnapshot = "Press DETECT to populate gateway / adapter info.";
        public string NetworkSnapshot
        {
            get => _networkSnapshot;
            set => Set(ref _networkSnapshot, value);
        }

        public ObservableCollection<DeviceVm> Devices { get; } = new();

        private string _devicesHint = "";
        public string DevicesHint
        {
            get => _devicesHint;
            set => Set(ref _devicesHint, value);
        }

        private string _routerFooter =
            "Tip: This list is best-effort (ping + ARP + reverse DNS). Some devices won't appear until they talk on the LAN.";
        public string RouterFooter
        {
            get => _routerFooter;
            set => Set(ref _routerFooter, value);
        }

        // ===================== COMMANDS =====================

        public ICommand ShowDomainsCommand { get; }
        public ICommand ShowRouterCommand { get; }
        public ICommand ShowDnsCommand { get; }

        public ICommand AddDomainCommand { get; }
        public ICommand RemoveSelectedDomainCommand { get; }
        public ICommand PreviewCommand { get; }
        public ICommand ApplyCommand { get; }
        public ICommand RevertCommand { get; }
        public ICommand RefreshCommand { get; }
        public ICommand FlushDnsCommand { get; }

        public ICommand ExportCsvCommand { get; }
        public ICommand ExportJsonCommand { get; }

        public ICommand RefreshDnsPanelCommand { get; }

        public ICommand DetectRouterCommand { get; }
        public ICommand ScanDevicesCommand { get; }
        public ICommand SaveDevicePoliciesCommand { get; }

        public MainViewModel()
        {
            _config = _configService.Load();
            Domains = new ObservableCollection<DomainEntry>(_config.BlockedDomains);

            ShowDomainsCommand = new RelayCommand(() => CurrentPage = PageKind.Domains);
            ShowRouterCommand = new RelayCommand(() => CurrentPage = PageKind.Router);
            ShowDnsCommand = new RelayCommand(() => CurrentPage = PageKind.Dns);

            AddDomainCommand = new RelayCommand(AddDomain);
            RemoveSelectedDomainCommand = new RelayCommand(RemoveSelectedDomain);
            PreviewCommand = new RelayCommand(Preview);
            ApplyCommand = new RelayCommand(Apply);
            RevertCommand = new RelayCommand(Revert);
            RefreshCommand = new RelayCommand(RefreshStatus);
            FlushDnsCommand = new RelayCommand(FlushDns);

            ExportCsvCommand = new RelayCommand(ExportCsv);
            ExportJsonCommand = new RelayCommand(ExportJson);

            RefreshDnsPanelCommand = new RelayCommand(RefreshDnsPanel);

            DetectRouterCommand = new RelayCommand(DetectRouter);
            ScanDevicesCommand = new RelayCommand(ScanDevices);
            SaveDevicePoliciesCommand = new RelayCommand(SaveDevicePolicies);

            RefreshStatus();
            RefreshActivity();
            RefreshDnsPanel();
            Preview();

            DetectRouter();
        }

        // ===================== DOMAIN BLOCKING =====================

        private void AddDomain()
        {
            try
            {
                LastError = "";

                var dom = HostsService.NormalizeDomain(NewDomain);
                if (string.IsNullOrWhiteSpace(dom) || !dom.Contains('.'))
                    return;

                if (Domains.Any(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase)))
                    return;

                var entry = new DomainEntry { Domain = dom };
                Domains.Add(entry);
                _config.BlockedDomains.Add(entry);

                _configService.Save(_config);
                SafeLog($"Added domain: {dom}", "INFO");

                NewDomain = "";
                Preview();
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Add domain failed", ex);
            }
        }

        private void RemoveSelectedDomain()
        {
            try
            {
                LastError = "";

                if (SelectedDomain == null)
                    return;

                var dom = SelectedDomain.Domain ?? "";

                Domains.Remove(SelectedDomain);

                var toRemove = _config.BlockedDomains
                    .Where(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var x in toRemove)
                    _config.BlockedDomains.Remove(x);

                _configService.Save(_config);
                SafeLog($"Removed domain: {dom}", "INFO");

                SelectedDomain = null;
                Preview();
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Remove domain failed", ex);
            }
        }

        private void Preview()
        {
            try
            {
                LastError = "";
                PreviewText = _hostsService.PreviewResult(_config);
            }
            catch (Exception ex)
            {
                Fail("Preview failed", ex);
            }
        }

        private void Apply()
        {
            try
            {
                LastError = "";

                _hostsService.Apply(_config);
                SafeLog("Hosts file applied", "INFO");

                RefreshStatus();
                Preview();
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Apply failed (admin?)", ex);
            }
        }

        private void Revert()
        {
            try
            {
                LastError = "";

                _hostsService.Revert();
                SafeLog("Hosts file reverted", "INFO");

                RefreshStatus();
                Preview();
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Revert failed (admin?)", ex);
            }
        }

        private void RefreshStatus()
        {
            try
            {
                LastError = "";
                HostsBlockActive = _hostsService.IsBlockPresent();
            }
            catch (Exception ex)
            {
                Fail("Status refresh failed", ex);
            }
        }

        private void FlushDns()
        {
            try
            {
                LastError = "";

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var p = System.Diagnostics.Process.Start(psi);
                p?.WaitForExit(6000);

                SafeLog("DNS cache flushed (ipconfig /flushdns)", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("DNS flush failed", ex, level: "WARN");
            }
        }

        // ===================== ACTIVITY / EXPORT =====================

        private void RefreshActivity()
        {
            try
            {
                ActivityLines.Clear();

                var last = _logService.ReadLast(120);
                foreach (var e in last)
                {
                    var line = $"{e.AtUtc:yyyy-MM-dd HH:mm:ss} | {e.Level} | {e.Message}";
                    ActivityLines.Add(line);
                }
            }
            catch { }
        }

        private void ExportCsv()
        {
            try
            {
                LastError = "";

                var last = _logService.ReadLast(200);
                var csv = _exportService.ExportActivityCsv(last);

                var path = _fileDialog.SaveFile(
                    "CSV file (*.csv)|*.csv|All files (*.*)|*.*",
                    ".csv",
                    "hostsguardian_activity.csv"
                );

                if (string.IsNullOrWhiteSpace(path))
                    return;

                File.WriteAllText(path, csv);
                SafeLog($"Exported activity CSV: {path}", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("CSV export failed", ex);
            }
        }

        private void ExportJson()
        {
            try
            {
                LastError = "";

                var last = _logService.ReadLast(200);
                var json = _exportService.ExportActivityJson(last);

                var path = _fileDialog.SaveFile(
                    "JSON file (*.json)|*.json|All files (*.*)|*.*",
                    ".json",
                    "hostsguardian_activity.json"
                );

                if (string.IsNullOrWhiteSpace(path))
                    return;

                File.WriteAllText(path, json);
                SafeLog($"Exported activity JSON: {path}", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("JSON export failed", ex);
            }
        }

        // ===================== DNS PANEL =====================

        private void RefreshDnsPanel()
        {
            try
            {
                LastError = "";
                DnsSnapshot = _dnsPanel.GetSnapshot();
                SafeLog("DNS panel refreshed (info-only)", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("DNS panel refresh failed", ex, level: "WARN");
            }
        }

        // ===================== ROUTER / DEVICES =====================

        private void DetectRouter()
        {
            try
            {
                LastError = "";

                _router = _routerDetect.Detect();

                RouterSummaryLine1 = $"Gateway: {_router.GatewayIpv4 ?? "(unknown)"}";
                RouterSummaryLine2 = $"Adapter: {_router.AdapterName ?? "(unknown)"}";
                RouterSummaryLine3 = $"Local IP: {_router.LocalIpv4 ?? "(unknown)"}";

                NetworkSnapshot = _routerDetect.BuildSnapshotText(_router);
                SafeLog("Router detection refreshed (info-only)", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Router detection failed", ex, level: "WARN");
            }
        }

        private void ScanDevices()
        {
            try
            {
                LastError = "";

                Devices.Clear();
                DevicesHint = "Scanning...";

                System.Threading.Tasks.Task.Run(() =>
                {
                    var results = _networkScan.ScanLanBestEffort(maxHostsToProbe: 96, timeoutMs: 140);

                    var policies = _config.DevicePolicies ?? new();

                    var vms = results
                        .OrderBy(x => x.Ip, StringComparer.OrdinalIgnoreCase)
                        .Select(dev =>
                        {
                            var p = policies.FirstOrDefault(x => string.Equals(x.Ip, dev.Ip, StringComparison.OrdinalIgnoreCase));
                            return new DeviceVm(dev, p?.Name, p?.Mac, p?.IsBlocked ?? false);
                        })
                        .ToList();

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Devices.Clear();
                        foreach (var vm in vms)
                            Devices.Add(vm);

                        DevicesHint = $"{Devices.Count} candidates";
                    });
                });

                SafeLog("Device scan started (best-effort)", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Device scan failed", ex, level: "WARN");
            }
        }

        private void SaveDevicePolicies()
        {
            try
            {
                LastError = "";

                _config.DevicePolicies ??= new();

                foreach (var d in Devices)
                {
                    if (string.IsNullOrWhiteSpace(d.Ip))
                        continue;

                    var p = _config.DevicePolicies.FirstOrDefault(x =>
                        string.Equals(x.Ip, d.Ip, StringComparison.OrdinalIgnoreCase));

                    if (p == null)
                    {
                        p = new DevicePolicy { Ip = d.Ip };
                        _config.DevicePolicies.Add(p);
                    }

                    p.IsBlocked = d.DnsBlocked;
                    p.Name = d.Name ?? "";
                    p.Mac = d.Mac ?? "";
                    p.UpdatedAtUtc = DateTime.UtcNow;
                }

                _configService.Save(_config);
                SafeLog("Device policies saved (config.json)", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Saving device policies failed", ex);
            }
        }

        // ===================== SAFE LOG / FAIL =====================

        private void SafeLog(string message, string level)
        {
            try { _logService.Write(message, level); }
            catch { }
        }

        private void Fail(string title, Exception ex, string level = "ERROR")
        {
            LastError = $"{title}: {ex.Message}";
            SafeLog($"{title}: {ex}", level);
            RefreshActivity();
        }
    }
}
