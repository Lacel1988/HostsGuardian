using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Infrastructure;
using HostsGuardian.Wpf.Services;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace HostsGuardian.Wpf.ViewModels
{
    public sealed class MainViewModel : ObservableObject
    {
        // ===== Core services =====
        private readonly ConfigService _configService = new();
        private readonly HostsService _hostsService = new();
        private readonly AuditLogService _logService = new();
        private readonly StatusExportService _exportService = new();
        private readonly HostsGuardian.Core.Services.NetworkScanService _networkScan = new();
        private readonly DnsEngineService _dnsEngine = new();

        // ===== WPF services =====
        private readonly FileDialogService _fileDialog = new();
        private readonly DnsPanelService _dnsPanel = new();
        private readonly HostsGuardian.Wpf.Services.RouterDetectService _routerDetect = new();

        private AppConfig _config;

        // ===================== SPA NAV (régi belső állapot) =====================

        private bool _isDomainsPage = true;
        public bool IsDomainsPage
        {
            get => _isDomainsPage;
            set
            {
                if (Set(ref _isDomainsPage, value))
                {
                    OnPropertyChanged(nameof(IsRouterPage));
                    OnPropertyChanged(nameof(IsActivityPage));

                    // új alias visibility-k frissítése
                    OnPropertyChanged(nameof(IsDomainsVisible));
                    OnPropertyChanged(nameof(IsRouterVisible));
                    OnPropertyChanged(nameof(IsDevicesVisible));
                    OnPropertyChanged(nameof(IsLogVisible));
                }
            }
        }

        private bool _isRouterPage;
        public bool IsRouterPage
        {
            get => _isRouterPage;
            set
            {
                if (Set(ref _isRouterPage, value))
                {
                    OnPropertyChanged(nameof(IsDomainsPage));
                    OnPropertyChanged(nameof(IsActivityPage));

                    OnPropertyChanged(nameof(IsDomainsVisible));
                    OnPropertyChanged(nameof(IsRouterVisible));
                    OnPropertyChanged(nameof(IsDevicesVisible));
                    OnPropertyChanged(nameof(IsLogVisible));
                }
            }
        }

        // régi "Activity" oldal, nálad erre volt építve az activity / log
        private bool _isActivityPage;
        public bool IsActivityPage
        {
            get => _isActivityPage;
            set
            {
                if (Set(ref _isActivityPage, value))
                {
                    OnPropertyChanged(nameof(IsDomainsPage));
                    OnPropertyChanged(nameof(IsRouterPage));

                    OnPropertyChanged(nameof(IsDomainsVisible));
                    OnPropertyChanged(nameof(IsRouterVisible));
                    OnPropertyChanged(nameof(IsDevicesVisible));
                    OnPropertyChanged(nameof(IsLogVisible));
                }
            }
        }

        // ===================== XAML kompatibilis oldalak (MainWindow.xaml ezt várja) =====================

        private bool _isDevicesPage;
        private bool _isLogPage;

        public bool IsDomainsVisible
        {
            get => IsDomainsPage;
            set { if (value) ShowDomains(); }
        }

        public bool IsRouterVisible
        {
            get => IsRouterPage;
            set { if (value) ShowRouter(); }
        }

        public bool IsDevicesVisible
        {
            get => _isDevicesPage;
            set { if (value) ShowDevices(); }
        }

        public bool IsLogVisible
        {
            get => _isLogPage;
            set { if (value) ShowLog(); }
        }

        // Page header texts (MainWindow.xaml)
        private string _currentPageTitle = "Domains";
        public string CurrentPageTitle
        {
            get => _currentPageTitle;
            private set => Set(ref _currentPageTitle, value);
        }

        private string _currentPageSubtitle = "Manage blocked domains (hosts / dns)";
        public string CurrentPageSubtitle
        {
            get => _currentPageSubtitle;
            private set => Set(ref _currentPageSubtitle, value);
        }

        private void SetPageHeader(string title, string subtitle)
        {
            CurrentPageTitle = title;
            CurrentPageSubtitle = subtitle;
        }

        // ===================== NAV COMMANDS (a MainWindow.xaml ezeket köti) =====================

        public ICommand ShowDomainsCommand { get; }
        public ICommand ShowRouterCommand { get; }

        public ICommand ShowDevicesCommand { get; }
        public ICommand ShowLogCommand { get; }

        public ICommand ShowActivityCommand { get; }

        private void ShowDomains()
        {
            IsDomainsPage = true;
            IsRouterPage = false;
            IsActivityPage = false;
            _isDevicesPage = false;
            _isLogPage = false;

            SetPageHeader("Domains", "Manage blocked domains (hosts / dns)");
        }

        private void ShowRouter()
        {
            IsDomainsPage = false;
            IsRouterPage = true;
            IsActivityPage = false;
            _isDevicesPage = false;
            _isLogPage = false;

            SetPageHeader("Router", "Detect gateway / check DNS engine");
        }

        private void ShowDevices()
        {
            IsDomainsPage = false;
            IsRouterPage = false;
            IsActivityPage = false;
            _isDevicesPage = true;
            _isLogPage = false;

            SetPageHeader("Devices", "Scan devices and manage DNS block policy");
        }

        private void ShowLog()
        {
            IsDomainsPage = false;
            IsRouterPage = false;
            IsActivityPage = true;
            _isDevicesPage = false;
            _isLogPage = true;

            SetPageHeader("Log", "Recent activity (audit log)");
            RefreshActivity();
        }

        private void ShowActivity()
        {
            ShowLog();
        }

        // ===================== DOMAIN BLOCKING =====================

        public ObservableCollection<DomainEntry> Domains { get; }

        private readonly ICollectionView _domainsView;
        public ICollectionView DomainsView => _domainsView;

        private DomainEntry? _selectedDomain;
        public DomainEntry? SelectedDomain
        {
            get => _selectedDomain;
            set
            {
                if (Set(ref _selectedDomain, value))
                {
                    BuildPreviewPanel();
                }
            }
        }

        private string _newDomain = "";
        public string NewDomainText
        {
            get => _newDomain;
            set => Set(ref _newDomain, value);
        }

        public string NewDomain
        {
            get => _newDomain;
            set => Set(ref _newDomain, value);
        }

        private string _search = "";
        public string SearchText
        {
            get => _search;
            set
            {
                if (Set(ref _search, value))
                    _domainsView.Refresh();
            }
        }

        public string Search
        {
            get => _search;
            set
            {
                if (Set(ref _search, value))
                    _domainsView.Refresh();
            }
        }

        // ===================== PREVIEW PANEL =====================

        private string _previewTitle = "Preview";
        public string PreviewTitle
        {
            get => _previewTitle;
            set => Set(ref _previewTitle, value);
        }

        private string _previewBody = "";
        public string PreviewBody
        {
            get => _previewBody;
            set => Set(ref _previewBody, value);
        }

        private void BuildPreviewPanel()
        {
            PreviewTitle = "Local hosts preview (pending)";
            try { PreviewBody = _hostsService.PreviewResult(_config); }
            catch (Exception ex) { PreviewBody = "Preview unavailable: " + ex.Message; }
        }

        private void DomainPolicyChanged(object? sender, PropertyChangedEventArgs e)
        {
            try
            {
                _configService.Save(_config);
                BuildPreviewPanel();
            }
            catch (Exception ex) { Fail("Saving domain selection failed", ex); }
        }

        // ===================== STATUS / LED =====================

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
            set
            {
                if (Set(ref _statusText, value))
                    OnPropertyChanged(nameof(StatusLedBrush));
            }
        }

        public Brush StatusLedBrush
        {
            get
            {
                if (HasError) return new SolidColorBrush(Color.FromRgb(0xFF, 0x3B, 0x3B));
                if (string.Equals(StatusText, "ACTIVE", StringComparison.OrdinalIgnoreCase))
                    return new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x66));
                return new SolidColorBrush(Color.FromRgb(0x44, 0x66, 0x55));
            }
        }

        // ===================== ERROR BANNER =====================

        private string _lastError = "";
        public string LastError
        {
            get => _lastError;
            set
            {
                if (Set(ref _lastError, value))
                {
                    OnPropertyChanged(nameof(HasError));
                    OnPropertyChanged(nameof(StatusLedBrush));
                }
            }
        }

        public bool HasError => !string.IsNullOrWhiteSpace(LastError);

        // ===================== TEXTS EXPECTED BY XAML =====================

        private string _adminHintText = "";
        public string AdminHintText
        {
            get => _adminHintText;
            set => Set(ref _adminHintText, value);
        }

        private string _domainInputHintText = "Add a domain, then select HOSTS and/or DNS before Apply/Push.";
        public string DomainInputHintText
        {
            get => _domainInputHintText;
            set => Set(ref _domainInputHintText, value);
        }

        // ===================== ACTIVITY / LOG =====================

        public ObservableCollection<ActivityItemVm> LogItems { get; } = new();

        private readonly ICollectionView _logView;
        public ICollectionView LogView => _logView;

        private ActivityItemVm? _selectedLog;
        public ActivityItemVm? SelectedLog
        {
            get => _selectedLog;
            set => Set(ref _selectedLog, value);
        }

        public ObservableCollection<string> ActivityLines { get; } = new();

        // ===================== DNS PANEL =====================

        private string _dnsSnapshot = "";
        public string DnsSnapshot
        {
            get => _dnsSnapshot;
            set => Set(ref _dnsSnapshot, value);
        }

        // ===================== ROUTER / DEVICES =====================

        private RouterDetectResult _router = RouterDetectResult.Empty();

        public string RouterIp => _router.GatewayIpv4 ?? "(unknown)";
        public string DnsTargetIp => _router.GatewayIpv4 ?? "(unknown)";
        public string EngineApiBaseUrl
        {
            get
            {
                try { return ManagementSecurity.Endpoint(_config.DnsEngine).AbsoluteUri.TrimEnd('/'); }
                catch { return "HTTPS endpoint not configured"; }
            }
        }
        public string EngineStatusText => DnsEngineStatusText;

        public string RouterSummaryText => $"{RouterSummaryLine1}\n{RouterSummaryLine2}\n{RouterSummaryLine3}\n\n{NetworkSnapshot}";

        private string _routerSummaryLine1 = "Gateway: (unknown)";
        public string RouterSummaryLine1
        {
            get => _routerSummaryLine1;
            set
            {
                if (Set(ref _routerSummaryLine1, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        private string _routerSummaryLine2 = "Adapter: (unknown)";
        public string RouterSummaryLine2
        {
            get => _routerSummaryLine2;
            set
            {
                if (Set(ref _routerSummaryLine2, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        private string _routerSummaryLine3 = "Local IP: (unknown)";
        public string RouterSummaryLine3
        {
            get => _routerSummaryLine3;
            set
            {
                if (Set(ref _routerSummaryLine3, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        private string _networkSnapshot = "Press DETECT to populate gateway / adapter info.";
        public string NetworkSnapshot
        {
            get => _networkSnapshot;
            set
            {
                if (Set(ref _networkSnapshot, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        public ObservableCollection<RouterCandidateVm> RouterCandidates { get; } = new();

        private readonly ICollectionView _routerCandidatesView;
        public ICollectionView RouterCandidatesView => _routerCandidatesView;

        private RouterCandidateVm? _selectedRouterCandidate;
        public RouterCandidateVm? SelectedRouterCandidate
        {
            get => _selectedRouterCandidate;
            set => Set(ref _selectedRouterCandidate, value);
        }

        // Devices
        public ObservableCollection<DeviceVm> Devices { get; } = new();
        public ICollectionView DevicesView => CollectionViewSource.GetDefaultView(Devices);

        private DeviceVm? _selectedDevice;
        public DeviceVm? SelectedDevice
        {
            get => _selectedDevice;
            set => Set(ref _selectedDevice, value);
        }

        private string _devicesHint = "";
        public string DevicesHint
        {
            get => _devicesHint;
            set => Set(ref _devicesHint, value);
        }

        public string DevicesSummaryText => string.IsNullOrWhiteSpace(DevicesHint) ? "Ready." : DevicesHint;

        // ===================== DNS ENGINE CONFIG =====================

        private bool _dnsEngineEnabled;
        public bool DnsEngineEnabled
        {
            get => _dnsEngineEnabled;
            set
            {
                if (Set(ref _dnsEngineEnabled, value))
                {
                    _config.DnsEngine.Enabled = value;

                    UpdateDnsEngineStatusText();
                }
            }
        }

        private string _dnsEngineBaseUrl = "";
        public string DnsEngineBaseUrl
        {
            get => _dnsEngineBaseUrl;
            set
            {
                if (Set(ref _dnsEngineBaseUrl, value))
                {
                    _config.DnsEngine.BaseUrl = value ?? "";

                    OnPropertyChanged(nameof(EngineApiBaseUrl));
                    UpdateDnsEngineStatusText();
                }
            }
        }

        private string _dnsEngineStatusText = "Not configured";
        public string DnsEngineStatusText
        {
            get => _dnsEngineStatusText;
            set
            {
                if (Set(ref _dnsEngineStatusText, value))
                    OnPropertyChanged(nameof(EngineStatusText));
            }
        }

        // ===================== COMMANDS =====================

        // Domains
        public ICommand AddDomainCommand { get; }
        public ICommand ClearNewDomainCommand { get; }
        public ICommand RemoveDomainCommand { get; }
        public ICommand ApplyHostsCommand { get; }
        public ICommand RevertHostsCommand { get; }
        public ICommand PushDnsCommand { get; }

        // Header right
        public ICommand RefreshCurrentPageCommand { get; }
        public ICommand ExportCommand { get; }

        // Top right
        public ICommand FlushDnsCommand { get; }

        // Router
        public ICommand DetectRouterCommand { get; }
        public ICommand PingEngineCommand { get; }
        public ICommand OpenRouterUiCommand { get; }

        // Devices
        public ICommand ScanDevicesCommand { get; }
        public ICommand SaveDevicesCommand { get; }
        public ICommand BlockSelectedDeviceCommand { get; }
        public ICommand UnblockSelectedDeviceCommand { get; }

        // Log
        public ICommand CopySelectedLogCommand { get; }
        public ICommand ClearLogCommand { get; }

        // ===================== INTERNAL COMMANDS =====================

        public ICommand RemoveSelectedDomainCommand { get; }
        public ICommand PreviewCommand { get; }
        public ICommand ApplyCommand { get; }
        public ICommand RevertCommand { get; }
        public ICommand RefreshCommand { get; }
        public ICommand ExportCsvCommand { get; }
        public ICommand ExportJsonCommand { get; }
        public ICommand RefreshActivityCommand { get; }
        public ICommand RefreshDnsPanelCommand { get; }
        public ICommand CopyPreviewCommand { get; }
        public ICommand ClearErrorCommand { get; }
        public ICommand RefreshNetworkSnapshotCommand { get; }
        public ICommand SaveDevicePoliciesCommand { get; }
        public ICommand TestDnsEngineCommand { get; }
        public ICommand PushDnsRulesCommand { get; }

        // ===================== CONSTRUCTOR =====================

        public MainViewModel()
        {
            _config = _configService.Load();
            _config.DevicePolicies ??= new();
            _config.DnsEngine ??= new DnsEngineConfig();
            _config.BlockedDomains ??= new System.Collections.Generic.List<DomainEntry>();

            DnsEngineEnabled = _config.DnsEngine.Enabled;
            DnsEngineBaseUrl = _config.DnsEngine.BaseUrl ?? "";


            Domains = new ObservableCollection<DomainEntry>(_config.BlockedDomains);
            foreach (var entry in Domains) entry.PropertyChanged += DomainPolicyChanged;

            _domainsView = CollectionViewSource.GetDefaultView(Domains);
            _domainsView.Filter = DomainFilter;

            _logView = CollectionViewSource.GetDefaultView(LogItems);
            _routerCandidatesView = CollectionViewSource.GetDefaultView(RouterCandidates);

            // ===== NAV =====
            ShowDomainsCommand = new RelayCommand(ShowDomains);
            ShowRouterCommand = new RelayCommand(ShowRouter);
            ShowDevicesCommand = new RelayCommand(ShowDevices);
            ShowLogCommand = new RelayCommand(ShowLog);
            ShowActivityCommand = new RelayCommand(ShowActivity);

            // ===== Internal commands =====
            AddDomainCommand = new RelayCommand(AddDomain);
            RemoveSelectedDomainCommand = new RelayCommand(RemoveSelectedDomain);
            PreviewCommand = new RelayCommand(Preview);
            ApplyCommand = new RelayCommand(Apply);
            RevertCommand = new RelayCommand(Revert);
            RefreshCommand = new RelayCommand(RefreshStatus);
            FlushDnsCommand = new RelayCommand(FlushDns);

            RefreshActivityCommand = new RelayCommand(RefreshActivity);
            ExportCsvCommand = new RelayCommand(ExportCsv);
            ExportJsonCommand = new RelayCommand(ExportJson);

            RefreshDnsPanelCommand = new RelayCommand(RefreshDnsPanel);
            CopyPreviewCommand = new RelayCommand(CopyPreview);
            ClearErrorCommand = new RelayCommand(() => LastError = "");

            DetectRouterCommand = new RelayCommand(DetectRouter);
            RefreshNetworkSnapshotCommand = new RelayCommand(RefreshNetworkSnapshot);
            ScanDevicesCommand = new RelayCommand(ScanDevices);
            SaveDevicePoliciesCommand = new RelayCommand(SaveDevicePolicies);

            TestDnsEngineCommand = new RelayCommand(TestDnsEngine);
            PushDnsRulesCommand = new RelayCommand(PushDnsRules);

            // ===== XAML alias commands =====
            ClearNewDomainCommand = new RelayCommand(() => NewDomainText = "");
            RemoveDomainCommand = RemoveSelectedDomainCommand;

            ApplyHostsCommand = ApplyCommand;
            RevertHostsCommand = RevertCommand;

            PingEngineCommand = TestDnsEngineCommand;
            PushDnsCommand = PushDnsRulesCommand;

            SaveDevicesCommand = SaveDevicePoliciesCommand;

            BlockSelectedDeviceCommand = new RelayCommand(() =>
            {
                if (SelectedDevice != null) SelectedDevice.DnsBlocked = true;
            });

            UnblockSelectedDeviceCommand = new RelayCommand(() =>
            {
                if (SelectedDevice != null) SelectedDevice.DnsBlocked = false;
            });

            OpenRouterUiCommand = new RelayCommand(OpenRouterUi);

            RefreshCurrentPageCommand = new RelayCommand(RefreshCurrentPage);
            ExportCommand = ExportJsonCommand;

            CopySelectedLogCommand = new RelayCommand(CopySelectedLog);
            ClearLogCommand = new RelayCommand(ClearLog);

            // ===== Admin hint =====
            try
            {
                AdminHintText = AdminService.IsAdmin()
                    ? "Admin: OK"
                    : "WARNING: Not running as Administrator. Apply/Revert will fail.";
            }
            catch
            {
                AdminHintText = "Admin check unavailable.";
            }

            // initial
            RefreshStatus();
            RefreshActivity();
            RefreshDnsPanel();
            Preview();
            DetectRouter();
            UpdateDnsEngineStatusText();

            ShowDomains();
        }

        private bool DomainFilter(object obj)
        {
            if (obj is not DomainEntry d)
                return false;

            if (string.IsNullOrWhiteSpace(SearchText))
                return true;

            var s = (d.Domain ?? "").Trim();
            return s.IndexOf(SearchText.Trim(), StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // ===================== DOMAIN BLOCKING =====================

        private void AddDomain()
        {
            try
            {
                LastError = "";

                var dom = HostsService.NormalizeDomain(NewDomainText);
                if (string.IsNullOrWhiteSpace(dom) || !dom.Contains('.'))
                    return;

                if (Domains.Any(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase)))
                    return;

                var entry = new DomainEntry { Domain = dom };
                entry.PropertyChanged += DomainPolicyChanged;
                Domains.Add(entry);
                _config.BlockedDomains.Add(entry);

                _configService.Save(_config);
                SafeLog($"Added domain: {dom}", "INFO");

                NewDomainText = "";
                BuildPreviewPanel();
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

                SelectedDomain.PropertyChanged -= DomainPolicyChanged;
                Domains.Remove(SelectedDomain);

                var toRemove = _config.BlockedDomains
                    .Where(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var x in toRemove)
                    _config.BlockedDomains.Remove(x);

                _configService.Save(_config);
                SafeLog($"Removed domain: {dom}", "INFO");

                SelectedDomain = null;
                BuildPreviewPanel();
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
                BuildPreviewPanel();
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

                var (ok, message) = _hostsService.Apply(_config);
                if (!ok) { LastError = "Hosts apply failed: " + message; SafeLog(LastError, "ERROR"); RefreshActivity(); return; }
                SafeLog(message, "INFO");

                RefreshStatus();
                BuildPreviewPanel();
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

                var (ok, message) = _hostsService.Revert();
                if (!ok) { LastError = "Hosts revert failed: " + message; SafeLog(LastError, "ERROR"); RefreshActivity(); return; }
                SafeLog(message, "INFO");

                RefreshStatus();
                BuildPreviewPanel();
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
                LogItems.Clear();

                var last = _logService.ReadLast(200);
                foreach (var e in last)
                {
                    var line = $"{e.AtUtc:yyyy-MM-dd HH:mm:ss} | {e.Level} | {e.Message}";
                    ActivityLines.Add(line);

                    LogItems.Add(new ActivityItemVm(e.AtUtc, e.Level ?? "INFO", e.Message ?? ""));
                }
            }
            catch (Exception ex)
            {
                Fail("Activity refresh failed", ex, level: "WARN");
            }
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

        private void CopyPreview()
        {
            try
            {
                LastError = "";

                if (SelectedDomain == null) return;

                var dom = SelectedDomain.Domain ?? "";
                if (!string.IsNullOrWhiteSpace(dom))
                    Clipboard.SetText(dom);

                SafeLog("Preview copied to clipboard", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Copy preview failed", ex, level: "WARN");
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

                RefreshNetworkSnapshot();

                RouterCandidates.Clear();
                if (!string.IsNullOrWhiteSpace(_router.GatewayIpv4))
                {
                    RouterCandidates.Add(new RouterCandidateVm
                    {
                        Ip = _router.GatewayIpv4 ?? "",
                        Type = "Gateway",
                        Score = 100,
                        Details = $"Adapter: {_router.AdapterName ?? "(unknown)"}"
                    });
                }

                OnPropertyChanged(nameof(RouterIp));
                OnPropertyChanged(nameof(DnsTargetIp));
                OnPropertyChanged(nameof(EngineApiBaseUrl));
                OnPropertyChanged(nameof(EngineStatusText));
                OnPropertyChanged(nameof(RouterSummaryText));

                SafeLog("Router detection refreshed (info-only)", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Router detection failed", ex, level: "WARN");
            }
        }

        private void RefreshNetworkSnapshot()
        {
            try
            {
                LastError = "";
                NetworkSnapshot = _routerDetect.BuildSnapshotText(_router);

                DevicesHint = string.IsNullOrWhiteSpace(_router.GatewayIpv4)
                    ? "No gateway"
                    : $"Gateway {_router.GatewayIpv4}";
            }
            catch (Exception ex)
            {
                Fail("Network snapshot failed", ex, level: "WARN");
            }
        }

        private void OpenRouterUi()
        {
            try
            {
                LastError = "";

                var ip = _router.GatewayIpv4;
                if (string.IsNullOrWhiteSpace(ip))
                    return;

                var url = "http://" + ip.Trim();
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });

                SafeLog($"Opened router UI: {url}", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Open router UI failed", ex, level: "WARN");
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
                    // FONTOS: ez best-effort scan, nem nyúl a routerhez
                    var results = _networkScan.ScanLanBestEffort(maxHostsToProbe: 196, timeoutMs: 200);

                    var policies = _config.DevicePolicies ?? new();

                    var vms = results
                        .OrderBy(x => x.Ip, StringComparer.OrdinalIgnoreCase)
                        .Select(dev =>
                        {
                            var p = DevicePolicyIdentity.Find(policies, dev.Mac);
                            var name = p?.Name;
                            var blocked = p?.IsBlocked ?? false;

                            // --- KONVERTÁLÁS NetworkDevice-re ---
                            var nd = new NetworkDevice
                            {
                                Ip = dev.Ip ?? "",
                                Mac = dev.Mac ?? "",
                                Hostname = dev.Hostname ?? "",
                                VendorHint = "" // ha később lesz OUI lookup, ide jön
                            };

                            return new DeviceVm(nd, name, blocked);
                        })
                        .ToList();

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Devices.Clear();
                        foreach (var vm in vms)
                            Devices.Add(vm);

                        DevicesHint = $"{Devices.Count} online device(s)";
                        OnPropertyChanged(nameof(DevicesSummaryText));
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

                var identified = Devices.Where(d => DevicePolicyIdentity.NormalizeMac(d.Mac).Length > 0).ToList();
                foreach (var d in identified)
                {
                    var mac = DevicePolicyIdentity.NormalizeMac(d.Mac);
                    if (_config.DevicePolicies.Count(p => DevicePolicyIdentity.NormalizeMac(p.Mac) == mac) > 1)
                        throw new InvalidDataException("Duplicate MAC policies require review.");
                }
                foreach (var d in identified)
                    DevicePolicyIdentity.Save(_config.DevicePolicies, d.Ip, d.Mac, d.Name ?? "", d.DnsBlocked);
                var unidentified = Devices.Count - identified.Count;

                _configService.Save(_config);
                SafeLog($"Device policies saved. {unidentified} row(s) without an observed MAC were not saved; legacy IP-only policies remain unassigned.", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Saving device policies failed", ex);
            }
        }

        // ===================== DNS ENGINE ACTIONS =====================

        private void UpdateDnsEngineStatusText()
        {
            if (!_config.DnsEngine.Enabled)
            {
                DnsEngineStatusText = "Disabled";
                return;
            }

            if (string.IsNullOrWhiteSpace(_config.DnsEngine.BaseUrl))
            {
                DnsEngineStatusText = "Missing BaseUrl";
                return;
            }

            DnsEngineStatusText = _config.DnsEngine.LastSeenUtc.HasValue
                ? $"Last OK: {_config.DnsEngine.LastSeenUtc.Value:HH:mm:ss} UTC"
                : "Configured";
        }

        public void OpenEngineSettings()
        {
            var dialog = new HostsGuardian.Wpf.EngineConnectionWindow(_config, _configService) { Owner = Application.Current.MainWindow };
            dialog.ShowDialog();
            _dnsEngineBaseUrl = _config.DnsEngine.BaseUrl;
            OnPropertyChanged(nameof(DnsEngineBaseUrl));
            OnPropertyChanged(nameof(EngineApiBaseUrl));
            UpdateDnsEngineStatusText();
        }

        private void TestDnsEngine()
        {
            try
            {
                LastError = "";

                System.Threading.Tasks.Task.Run(async () =>
                {
                    var (ok, msg) = await _dnsEngine.TestAsync(_config.DnsEngine).ConfigureAwait(false);

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (!ok) LastError = "DNS Engine test: " + msg;
                        SafeLog("DNS Engine test: " + msg, ok ? "INFO" : "WARN");

                        UpdateDnsEngineStatusText();
                        RefreshActivity();

                        OnPropertyChanged(nameof(EngineStatusText));
                    });
                });
            }
            catch (Exception ex)
            {
                Fail("DNS Engine test failed", ex, level: "WARN");
            }
        }

        private void PushDnsRules()
        {
            try
            {
                LastError = "";

                // Capture only explicitly selected DNS policy before starting background work.
                var domains = DomainPolicySelection.ForDns(_config.BlockedDomains);
                _configService.Save(_config);

                System.Threading.Tasks.Task.Run(async () =>
                {
                    var (ok, msg) = await _dnsEngine.PushBlockedDomainsAsync(_config.DnsEngine, domains).ConfigureAwait(false);

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (!ok) LastError = "Push rules: " + msg;
                        SafeLog("Push rules: " + msg, ok ? "INFO" : "WARN");
                        _configService.Save(_config);
                        UpdateDnsEngineStatusText();
                        RefreshActivity();

                        OnPropertyChanged(nameof(EngineStatusText));
                    });
                });
            }
            catch (Exception ex)
            {
                Fail("Push rules failed", ex, level: "WARN");
            }
        }

        // ===================== LOG COMMAND IMPLEMENTATIONS =====================

        private void CopySelectedLog()
        {
            try
            {
                LastError = "";
                if (SelectedLog == null) return;

                var text = $"{SelectedLog.Time} | {SelectedLog.Level} | {SelectedLog.Message}";
                Clipboard.SetText(text);

                SafeLog("Selected log copied", "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail("Copy selected log failed", ex, level: "WARN");
            }
        }

        private void ClearLog()
        {
            try
            {
                LastError = "";
                LogItems.Clear();
                ActivityLines.Clear();
                SafeLog("Log cleared (UI only)", "INFO");
            }
            catch (Exception ex)
            {
                Fail("Clear log failed", ex, level: "WARN");
            }
        }

        // ===================== REFRESH CURRENT PAGE =====================

        private void RefreshCurrentPage()
        {
            RefreshStatus();
            RefreshActivity();
            RefreshDnsPanel();
            BuildPreviewPanel();
            UpdateDnsEngineStatusText();

            OnPropertyChanged(nameof(StatusLedBrush));
            OnPropertyChanged(nameof(RouterIp));
            OnPropertyChanged(nameof(EngineApiBaseUrl));
            OnPropertyChanged(nameof(EngineStatusText));
            OnPropertyChanged(nameof(RouterSummaryText));
            OnPropertyChanged(nameof(DevicesSummaryText));
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

        // ===================== INTERNAL VM TYPE FOR ROUTER GRID =====================

        public sealed class RouterCandidateVm
        {
            public string Ip { get; set; } = "";
            public string Type { get; set; } = "";
            public int Score { get; set; }
            public string Details { get; set; } = "";
        }
    }
}