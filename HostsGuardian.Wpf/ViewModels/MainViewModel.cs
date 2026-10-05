using L = HostsGuardian.Wpf.Localization.LocalizationService;
using System.Collections.Immutable;
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
        private System.Windows.Threading.DispatcherTimer? _statusTimer;
        private readonly bool _initializeNetwork;
        public NotificationCenter Notifications { get; }
        public LanguageChoice[] Languages { get; } = { new("en", "English"), new("hu", "Magyar") };
        public sealed record LanguageChoice(string Code, string Name);
        public string SelectedLanguage
        {
            get => L.Instance.Language;
            set { try { L.Instance.ChangeLanguage(value); } catch (Exception ex) { LastError = L.T("Language preference could not be saved") + ": " + ex.Message; OnPropertyChanged(); } }
        }
        public bool NotifyEngine { get => UiPreferences.Current.Data.EngineDns; set => SetPreference(NotificationCategory.EngineDns, value); }
        public bool NotifyPolicy { get => UiPreferences.Current.Data.Policy; set => SetPreference(NotificationCategory.Policy, value); }
        public bool NotifyDevices { get => UiPreferences.Current.Data.NewDevices; set => SetPreference(NotificationCategory.NewDevices, value); }
        public bool NotifyRecovery { get => UiPreferences.Current.Data.Recovery; set => SetPreference(NotificationCategory.Recovery, value); }
        private void SetPreference(NotificationCategory category, bool value)
        { try { UiPreferences.Current.SetEnabled(category, value); } catch { LastError = L.T("Notification preferences could not be saved"); } OnPropertyChanged(string.Empty); }
        private bool _notificationsOpen;
        public bool NotificationsOpen { get => _notificationsOpen; set => Set(ref _notificationsOpen, value); }
        public ICommand ToggleNotificationsCommand => new RelayCommand(() => NotificationsOpen = !NotificationsOpen);
        public ICommand MarkNotificationsReadCommand => new RelayCommand(() => Notifications.MarkAllRead());
        public void OpenNotification(NotificationItem item)
        {
            Notifications.MarkRead(item);
            if (item.Page == "Devices") ShowDevices(); else if (item.Page == "Domains") ShowDomains(); else ShowRouter();
            NotificationsOpen = false;
        }
        private void ObserveDraftSaveFailure(bool failed) => Notifications.Observe("local-draft", failed, NotificationCategory.Policy,
            NotificationSeverity.Warning, "Draft could not be saved", "The local draft was not saved. Review the error before sending changes.", "Devices");
        private void ObservePolicyFailure(bool failed) => Notifications.Observe("policy", failed, NotificationCategory.Policy,
            NotificationSeverity.Warning, "Policy update not confirmed", "The Engine has not confirmed this change. Review the error and read back the policy.", "Domains");
        private void ObserveConnection(ConnectionResult result)
        {
            if (result.State is ConnectionState.Timeout or ConnectionState.Unreachable or ConnectionState.NetworkFailure)
                Notifications.Observe("engine", true, NotificationCategory.EngineDns, NotificationSeverity.Critical,
                    "Engine unreachable", "HostsGuardian cannot reach the DNS Engine.", "Router");
            if (result.State is ConnectionState.AuthenticationFailed or ConnectionState.CredentialUnavailable or ConnectionState.TrustFailure)
                Notifications.Observe("security", true, NotificationCategory.EngineDns, NotificationSeverity.Critical,
                    "Connection security problem", "Management authentication or certificate verification failed. Review the connection settings.", "Router");
            if (!result.Ok || result.Transport == null) return;
            Notifications.Observe("engine", false, NotificationCategory.EngineDns, NotificationSeverity.Critical, "", "", "Router");
            Notifications.Observe("security", false, NotificationCategory.EngineDns, NotificationSeverity.Critical, "", "", "Router");
            var status = result.Transport;
            Notifications.Observe("dns", !(status.UdpListening && status.TcpListening), NotificationCategory.EngineDns,
                NotificationSeverity.Critical, "DNS service failure", "The Engine reports that one or both DNS listeners are not running.", "Router");
            Notifications.Observe("persistence", status.PersistenceFault != "", NotificationCategory.Policy,
                NotificationSeverity.Critical, "Policy persistence problem", "The Engine reports a persistence fault. Review status details before sending changes.", "Domains");
            if (_engineStatus.Upstream != "UNKNOWN") Notifications.Observe("upstream", _engineStatus.Upstream is "FAILED" or "DEGRADED", NotificationCategory.EngineDns,
                NotificationSeverity.Warning, "Upstream degraded", "A fresh Engine observation reports an upstream failure or fallback use.", "Router");
        }
        public string[] LogLevels { get; } = { "ALL", "INFO", "WARN", "ERROR" };
        private string _selectedLogLevel = "ALL";
        public string SelectedLogLevel { get => _selectedLogLevel; set { if (Set(ref _selectedLogLevel, value)) _logView.Refresh(); } }
        private void LanguageChanged(object? sender, EventArgs args) => Relocalize();
        private void Relocalize()
        {
            if (IsDevicesVisible) SetPageHeader(L.T("Devices"), L.T("Scan devices and manage DNS block policy"));
            else if (IsRouterVisible) SetPageHeader(L.T("Router"), L.T("Detect gateway / check DNS engine"));
            else if (IsLogVisible) SetPageHeader(L.T("Log"), L.T("Recent activity (audit log)"));
            else SetPageHeader(L.T("Domains"), L.T("Choose domains for the DNS Engine policy"));
            DomainInputHintText = L.T("Add a domain, select DNS filtering, then send the policy to the Engine.");
            RouterSummaryLine1 = L.F("Gateway: {0}", _router.GatewayIpv4 ?? L.T("(unknown)"));
            RouterSummaryLine2 = L.F("Adapter: {0}", _router.AdapterName ?? L.T("(unknown)"));
            RouterSummaryLine3 = L.F("Local IP: {0}", _router.LocalIpv4 ?? L.T("(unknown)"));
            NetworkSnapshot = L.F("Adapter: {0}\nLocal IPv4: {1}\nGateway: {2}\nDNS servers: {3}", _router.AdapterName ?? L.T("unknown"), _router.LocalIpv4 ?? L.T("unknown"), _router.GatewayIpv4 ?? L.T("unknown"), _initializeNetwork ? DnsTargetIp : L.T("unknown"));
            BuildPreviewPanel(); UpdateDnsEngineStatusText(); Notifications.Relocalize();
            foreach (var device in Devices) device.Relocalize();
            foreach (var row in DeviceDomainRules) row.Relocalize();
            foreach (var log in LogItems) log.Relocalize();
            OnPropertyChanged(string.Empty);
        }
        public void Dispose() { _statusTimer?.Stop(); L.Instance.LanguageChanged -= LanguageChanged; }

        // ===== Core services =====
        private readonly ConfigService _configService;
        private readonly AuditLogService _logService;
        private readonly StatusExportService _exportService = new();
        private readonly HostsGuardian.Core.Services.NetworkScanService _networkScan = new();
        private readonly DnsEngineService _dnsEngine = new();
        private readonly EngineStatusPresentation _engineStatus = new();
        private bool _engineRequestPending;
        private int _engineSettingsGeneration;

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
        private string _currentPageTitle = L.T("Domains");
        public string CurrentPageTitle
        {
            get => _currentPageTitle;
            private set => Set(ref _currentPageTitle, value);
        }

        private string _currentPageSubtitle = L.T("Choose domains for the DNS Engine policy");
        public string CurrentPageSubtitle
        {
            get => _currentPageSubtitle;
            private set => Set(ref _currentPageSubtitle, value);
        }

        private void NotifyNavigation()
        {
            OnPropertyChanged(nameof(IsDomainsVisible)); OnPropertyChanged(nameof(IsRouterVisible));
            OnPropertyChanged(nameof(IsDevicesVisible)); OnPropertyChanged(nameof(IsLogVisible));
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

            NotifyNavigation();
            SetPageHeader(L.T("Domains"), L.T("Choose domains for the DNS Engine policy"));
        }

        private void ShowRouter()
        {
            IsDomainsPage = false;
            IsRouterPage = true;
            IsActivityPage = false;
            _isDevicesPage = false;
            _isLogPage = false;

            NotifyNavigation();
            SetPageHeader(L.T("Router"), L.T("Detect gateway / check DNS engine"));
        }

        private void ShowDevices()
        {
            IsDomainsPage = false;
            IsRouterPage = false;
            IsActivityPage = false;
            _isDevicesPage = true;
            _isLogPage = false;

            NotifyNavigation();
            SetPageHeader(L.T("Devices"), L.T("Scan devices and manage DNS block policy"));
        }

        private void ShowLog()
        {
            IsDomainsPage = false;
            IsRouterPage = false;
            IsActivityPage = true;
            _isDevicesPage = false;
            _isLogPage = true;

            NotifyNavigation();
            SetPageHeader(L.T("Log"), L.T("Recent activity (audit log)"));
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

        private string _previewTitle = L.T("Preview");
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
            PreviewTitle = L.T("Selected DNS domains (not yet sent)");
            try { PreviewBody = string.Join(Environment.NewLine, DomainPolicySelection.ForDns(_config.BlockedDomains)); }
            catch (Exception ex) { PreviewBody = L.T("Preview unavailable: ") + ex.Message; }
        }

        private void DomainPolicyChanged(object? sender, PropertyChangedEventArgs e)
        {
            _engineStatus.InvalidateSelection();
            UpdateDnsEngineStatusText();
            try
            {
                _configService.Save(_config);
                BuildPreviewPanel();
                RefreshDeviceDetail();
            }
            catch (Exception ex) { Fail(L.T("Saving domain selection failed"), ex); }
        }

        // ===================== ERROR BANNER =====================

        private string _lastError = "";
        public string LastError
        {
            get => L.Display(_lastError);
            set
            {
                if (Set(ref _lastError, value))
                {
                    OnPropertyChanged(nameof(HasError));
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

        private string _domainInputHintText = L.T("Add a domain, select DNS filtering, then send the policy to the Engine.");
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

        public string RouterIp => _router.GatewayIpv4 ?? L.T("(unknown)");
        public string DnsTargetIp => string.Join(", ", new HostsGuardian.Wpf.Services.DnsStateService().GetState().Servers);
        public string EngineApiBaseUrl
        {
            get
            {
                try { return ManagementSecurity.Endpoint(_config.DnsEngine).AbsoluteUri.TrimEnd('/'); }
                catch { return L.T("HTTPS endpoint not configured"); }
            }
        }
        public string EngineStatusText => DnsEngineStatusText;

        public string RouterSummaryText => $"{RouterSummaryLine1}\n{RouterSummaryLine2}\n{RouterSummaryLine3}\n\n{NetworkSnapshot}";

        private string _routerSummaryLine1 = L.T("Gateway: (unknown)");
        public string RouterSummaryLine1
        {
            get => _routerSummaryLine1;
            set
            {
                if (Set(ref _routerSummaryLine1, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        private string _routerSummaryLine2 = L.T("Adapter: (unknown)");
        public string RouterSummaryLine2
        {
            get => _routerSummaryLine2;
            set
            {
                if (Set(ref _routerSummaryLine2, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        private string _routerSummaryLine3 = L.T("Local IP: (unknown)");
        public string RouterSummaryLine3
        {
            get => _routerSummaryLine3;
            set
            {
                if (Set(ref _routerSummaryLine3, value))
                    OnPropertyChanged(nameof(RouterSummaryText));
            }
        }

        private string _networkSnapshot = L.T("Press DETECT to populate gateway / adapter info.");
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
            set { if (Set(ref _selectedDevice, value)) RefreshDeviceDetail(); }
        }

        private string _devicesHint = "";
        public string DevicesHint
        {
            get => _devicesHint;
            set => Set(ref _devicesHint, value);
        }

        public string DevicesSummaryText => string.IsNullOrWhiteSpace(DevicesHint) ? L.T("Ready.") : DevicesHint;

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
                    _engineSettingsGeneration++;
                    _engineStatus.Reset();
            _fullPolicyBaseline = null;

                    OnPropertyChanged(nameof(EngineApiBaseUrl));
                    UpdateDnsEngineStatusText();
                }
            }
        }

        private string _dnsEngineStatusText = L.T("Not configured");
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

        // Log
        public ICommand CopySelectedLogCommand { get; }
        public ICommand ClearLogCommand { get; }

        // ===================== INTERNAL COMMANDS =====================

        public ICommand RemoveSelectedDomainCommand { get; }
        public ICommand PreviewCommand { get; }
        public ICommand RefreshCommand { get; }
        public ICommand ExportCsvCommand { get; }
        public ICommand ExportJsonCommand { get; }
        public ICommand RefreshActivityCommand { get; }
        public ICommand RefreshDnsPanelCommand { get; }
        public ICommand CopyPreviewCommand { get; }
        public ICommand ClearErrorCommand { get; }
        public ICommand RefreshNetworkSnapshotCommand { get; }
        public ICommand SaveDevicePoliciesCommand { get; }
        public ICommand EnterEngineSafeModeCommand { get; }
        public ICommand ExitEngineSafeModeCommand { get; }
        public string EngineSafeModeText => L.T(_engineStatus.SafeMode);
        public string EngineStatusDetailsText => _engineStatus.Current is not { } status ? L.T("Current status details: Unknown / unconfirmed") :
            L.F("Revision: {0}; instance: {1}\nGlobal rules: {2}/{3}; device rules: {4}/{5}\nPolicy loaded: {6}; restore: {7}\nPersistence fault: {8}\nSafe Mode reason: {9}\nUpstream observation: {10}\nLast success: {11}; last failure: {12}\nHistorical failure does not establish a current outage.",
                status.PolicyRevision, status.InstanceId, status.CommittedRuleCount, status.ActiveRuleCount,
                status.CommittedDeviceOverrideCount, status.ActiveDeviceOverrideCount, status.PolicyLoaded, status.PolicyRestoreState,
                status.PersistenceFault == "" ? L.T("None reported") : status.PersistenceFault,
                status.SafeModeReason == "" ? L.T("None reported") : status.SafeModeReason, status.LastUpstreamOutcome,
                status.LastUpstreamSuccessUtc, status.LastUpstreamFailureUtc);
        public ICommand TestDnsEngineCommand { get; }
        public ICommand PushDnsRulesCommand { get; }

        // ===================== CONSTRUCTOR =====================

        public MainViewModel() : this(null, true) { }

        public MainViewModel(ConfigService? configService, bool initialize, AuditLogService? auditLog = null)
        {
            _initializeNetwork = initialize;
            _configService = configService ?? new();
            _logService = auditLog ?? new();
            _config = _configService.Load();
            Notifications = new NotificationCenter(foreground: () => Application.Current?.MainWindow?.IsActive ?? true);
            L.Instance.LanguageChanged += LanguageChanged;
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
            _logView.Filter = item => item is ActivityItemVm log && (SelectedLogLevel == "ALL" || log.Level == SelectedLogLevel);
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

            EnterEngineSafeModeCommand = new RelayCommand(EnterEngineSafeMode,
                () => !_engineRequestPending && _engineStatus.CanEnterSafeMode);
            ExitEngineSafeModeCommand = new RelayCommand(ExitEngineSafeMode,
                () => !_engineRequestPending && _engineStatus.CanExitSafeMode);
            TestDnsEngineCommand = new RelayCommand(TestDnsEngine);
            PushDnsRulesCommand = new RelayCommand(PushDnsRules);

            // ===== XAML alias commands =====
            ClearNewDomainCommand = new RelayCommand(() => NewDomainText = "");
            RemoveDomainCommand = RemoveSelectedDomainCommand;


            PingEngineCommand = TestDnsEngineCommand;
            PushDnsCommand = PushDnsRulesCommand;

            SaveDevicesCommand = SaveDevicePoliciesCommand;

            LoadFullPolicyCommand = new RelayCommand(LoadFullPolicy);
            ExplainSelectedPolicyCommand = new RelayCommand(ExplainSelectedPolicy);
            RegisterSelectedDeviceCommand = new RelayCommand(RegisterSelectedDevice);

            OpenRouterUiCommand = new RelayCommand(OpenRouterUi);

            RefreshCurrentPageCommand = new RelayCommand(RefreshCurrentPage);
            ExportCommand = ExportJsonCommand;

            CopySelectedLogCommand = new RelayCommand(CopySelectedLog);
            ClearLogCommand = new RelayCommand(ClearLog);

            if (initialize)
            {
            // initial
            RefreshStatus();
            RefreshActivity();
            RefreshDnsPanel();
            Preview();
            DetectRouter();
            UpdateDnsEngineStatusText();

            _statusTimer = new System.Windows.Threading.DispatcherTimer
            { Interval = TimeSpan.FromSeconds(5) };
            _statusTimer.Tick += (_, _) => UpdateDnsEngineStatusText();
            _statusTimer.Start();
            Application.Current.Exit += (_, _) => Dispose();
            }
            ShowDomains();
            Relocalize();
            if (UiPreferences.Current.LoadFailed) LastError = L.T("UI preferences could not be read; defaults are in use.");
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

                var dom = DomainName.Normalize(NewDomainText);
                if (string.IsNullOrWhiteSpace(dom) || !dom.Contains('.'))
                { LastError = L.T("Enter a valid domain such as example.com."); return; }

                if (Domains.Any(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase)))
                { LastError = L.T("This domain is already in the draft."); return; }

                var entry = new DomainEntry { Domain = dom };
                entry.PropertyChanged += DomainPolicyChanged;
                Domains.Add(entry);
                _config.BlockedDomains.Add(entry);
                _engineStatus.InvalidateSelection();
                UpdateDnsEngineStatusText();

                _configService.Save(_config);
                SafeLog(new ActivityEvent("WPF user action", "Policy", "Added domain: {0}", new[] { dom }, Target: dom, Action: "Add", Outcome: "LocalDraftSaved"), "INFO");

                NewDomainText = "";
                BuildPreviewPanel();
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Add domain failed"), ex);
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
                _engineStatus.InvalidateSelection();
                UpdateDnsEngineStatusText();

                _configService.Save(_config);
                SafeLog(new ActivityEvent("WPF user action", "Policy", "Removed domain: {0}", new[] { dom }, Target: dom, Action: "Remove", Outcome: "LocalDraftSaved"), "INFO");

                SelectedDomain = null;
                BuildPreviewPanel();
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Remove domain failed"), ex);
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
                Fail(L.T("Preview failed"), ex);
            }
        }

        private void RefreshStatus() => UpdateDnsEngineStatusText();

        private async void FlushDns()
        {
            LastError = "";
            try
            {
                var result = await new DnsCacheFlushService().FlushAsync();
                if (!result.Success) LastError = L.T(result.Message);
                SafeLog(L.T(result.Message), result.Success ? "INFO" : "WARN");
            }
            catch { LastError = L.T("Unable to clear this PC’s DNS cache."); }
            RefreshActivity();
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
                LastError = L.T("Activity refresh failed") + ": " + ex.Message;
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
                    L.T("CSV file (*.csv)|*.csv|All files (*.*)|*.*"),
                    ".csv",
                    "hostsguardian_activity.csv"
                );

                if (string.IsNullOrWhiteSpace(path))
                    return;

                File.WriteAllText(path, csv);
                SafeLog(L.F("Exported activity CSV: {0}", path), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("CSV export failed"), ex);
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
                    L.T("JSON file (*.json)|*.json|All files (*.*)|*.*"),
                    ".json",
                    "hostsguardian_activity.json"
                );

                if (string.IsNullOrWhiteSpace(path))
                    return;

                File.WriteAllText(path, json);
                SafeLog(L.F("Exported activity JSON: {0}", path), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("JSON export failed"), ex);
            }
        }

        // ===================== DNS PANEL =====================

        private void RefreshDnsPanel()
        {
            try
            {
                LastError = "";
                DnsSnapshot = _dnsPanel.GetSnapshot();
                SafeLog(L.T("DNS panel refreshed (info-only)"), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("DNS panel refresh failed"), ex, level: "WARN");
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

                SafeLog(L.T("Preview copied to clipboard"), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Copy preview failed"), ex, level: "WARN");
            }
        }

        // ===================== ROUTER / DEVICES =====================

        private void DetectRouter()
        {
            try
            {
                LastError = "";

                _router = _routerDetect.Detect();

                RouterSummaryLine1 = L.F("Gateway: {0}", _router.GatewayIpv4 ?? L.T("(unknown)"));
                RouterSummaryLine2 = L.F("Adapter: {0}", _router.AdapterName ?? L.T("(unknown)"));
                RouterSummaryLine3 = L.F("Local IP: {0}", _router.LocalIpv4 ?? L.T("(unknown)"));

                RefreshNetworkSnapshot();

                RouterCandidates.Clear();
                if (!string.IsNullOrWhiteSpace(_router.GatewayIpv4))
                {
                    RouterCandidates.Add(new RouterCandidateVm
                    {
                        Ip = _router.GatewayIpv4 ?? "",
                        Type = L.T("Gateway"),
                        Score = 100,
                        Details = L.F("Adapter: {0}", _router.AdapterName ?? L.T("(unknown)"))
                    });
                }

                OnPropertyChanged(nameof(RouterIp));
                OnPropertyChanged(nameof(DnsTargetIp));
                OnPropertyChanged(nameof(EngineApiBaseUrl));
                OnPropertyChanged(nameof(EngineStatusText));
                OnPropertyChanged(nameof(RouterSummaryText));

                SafeLog(L.T("Router detection refreshed (info-only)"), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Router detection failed"), ex, level: "WARN");
            }
        }

        private void RefreshNetworkSnapshot()
        {
            try
            {
                LastError = "";
                NetworkSnapshot = L.F("Adapter: {0}\nLocal IPv4: {1}\nGateway: {2}\nDNS servers: {3}", _router.AdapterName ?? L.T("unknown"), _router.LocalIpv4 ?? L.T("unknown"), _router.GatewayIpv4 ?? L.T("unknown"), DnsTargetIp);

                DevicesHint = string.IsNullOrWhiteSpace(_router.GatewayIpv4)
                    ? L.T("No gateway")
                    : L.F("Gateway {0}", _router.GatewayIpv4);
            }
            catch (Exception ex)
            {
                Fail(L.T("Network snapshot failed"), ex, level: "WARN");
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

                SafeLog(L.F("Opened router UI: {0}", url), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Open router UI failed"), ex, level: "WARN");
            }
        }

        private async void ScanDevices()
        {
            try
            {
                LastError = "";

                Devices.Clear();
                DevicesHint = L.T("Scanning...");

                await System.Threading.Tasks.Task.Run(() =>
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

                            var mac = DevicePolicyIdentity.NormalizeMac(nd.Mac);
                            var registered = _config.DeviceDomainPolicy.Devices.Where(d => d.Mac == mac && mac != "").ToArray();
                            return new DeviceVm(nd, registered.Length == 1 ? registered[0].Name : name, blocked)
                            { DeviceId = registered.Length == 1 ? registered[0].DeviceId : null, ObservedAtUtc = DateTimeOffset.UtcNow };
                        })
                        .ToList();

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Devices.Clear();
                        foreach (var vm in vms) Devices.Add(vm);
                        foreach (var registered in _config.DeviceDomainPolicy.Devices)
                            if (!Devices.Any(d => d.DeviceId == registered.DeviceId))
                                Devices.Add(new DeviceVm(new NetworkDevice { Mac = registered.Mac ?? "" }, registered.Name, false) { DeviceId = registered.DeviceId });

                        foreach (var unknown in vms)
                            Notifications.Observe("unknown." + (unknown.Mac == "" ? unknown.Ip : unknown.Mac), unknown.DeviceId == null, NotificationCategory.NewDevices,
                                NotificationSeverity.Warning, "Unknown device discovered", "A scan found a device without a registered identity. Review Devices before assigning policy.", "Devices");
                        DevicesHint = L.F("{0} recently observed device(s); Engine address binding requires explicit review.", Devices.Count);
                        OnPropertyChanged(nameof(DevicesSummaryText));
                    });
                });

                SafeLog(L.T("Device scan started (best-effort)"), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Device scan failed"), ex, level: "WARN");
            }
        }

        private void SaveDevicePolicies()
        {
            try
            {
                foreach (var device in Devices.Where(d => d.DeviceId != null))
                    _config.DeviceDomainPolicy = _config.DeviceDomainPolicy with
                    { Devices = _config.DeviceDomainPolicy.Devices.Select(d => d.DeviceId == device.DeviceId ? d with { Name = device.DisplayName } : d).ToImmutableArray() };
                _config.DeviceDomainPolicy = PolicyCanonicalization.Canonicalize(_config.DeviceDomainPolicy);
                _configService.Save(_config);
                LastError = ""; ObserveDraftSaveFailure(false);
                SafeLog(L.T("Registered device names saved to local draft; Engine policy unchanged"), "INFO");
                _engineStatus.InvalidateSelection(); UpdateDnsEngineStatusText(); RefreshDeviceDetail();
            }
            catch (Exception exception) { ObserveDraftSaveFailure(true); Fail(L.T("Saving device policy failed"), exception); }
        }

        private FullPolicyRead? _fullPolicyBaseline;
        public ICommand LoadFullPolicyCommand { get; }
        public ICommand ExplainSelectedPolicyCommand { get; }
        private DeviceDomainRuleVm? _selectedDeviceDomain;
        public DeviceDomainRuleVm? SelectedDeviceDomain { get => _selectedDeviceDomain; set { Set(ref _selectedDeviceDomain, value); _effectiveObservedUtc = null; OnPropertyChanged(nameof(EngineEffectivePolicy)); OnPropertyChanged(nameof(EngineEffectivePolicyDiagnostics)); } }
        private EffectivePolicyExplanation? _lastExplanation;
        private DateTimeOffset? _effectiveObservedUtc;
        private bool HasCurrentExplanation => _effectiveObservedUtc is { } observed && DateTimeOffset.UtcNow - observed <= EngineStatusPresentation.MaximumStatusAge && _lastExplanation != null;
        public string EngineEffectivePolicy => HasCurrentExplanation
            ? L.F("Engine decision: {0} ({1})", L.T(_lastExplanation!.Blocked ? "BLOCK" : "ALLOW"), L.T(_lastExplanation.Reason))
            : L.T("Engine effective policy: unknown; select a domain and check it.");
        public string EngineEffectivePolicyDiagnostics => HasCurrentExplanation ?
            L.F("Engine effective policy: {0}; {1}; identity {2}; DeviceId {3}; mapping generation {4}; policy revision {5}",
                L.T(_lastExplanation!.Blocked ? "BLOCK" : "ALLOW"), _lastExplanation.Reason, _lastExplanation.IdentityState,
                _lastExplanation.DeviceId?.ToString() ?? L.T("unknown"), _lastExplanation.MappingGeneration, _lastExplanation.Revision) : EngineEffectivePolicy;
        private async void ExplainSelectedPolicy()
        {
            if (_engineRequestPending || SelectedDevice == null || SelectedDeviceDomain == null) return;
            _engineRequestPending = true; LastError = "";
            var device = SelectedDevice; var row = SelectedDeviceDomain; var generation = _engineSettingsGeneration;
            try
            {
                var read = await _dnsEngine.ExplainPolicyAsync(_config.DnsEngine, device.Ip, row.Domain);
                if (generation != _engineSettingsGeneration || device != SelectedDevice || row != SelectedDeviceDomain) return;
                ObserveConnection(read.Connection);
                _effectiveObservedUtc = read.Connection.Ok ? DateTimeOffset.UtcNow : null;
                if (read.Explanation is { } explanation)
                {
                    _lastExplanation = explanation;
                    if (explanation.IdentityState is "Ambiguous" or "AmbiguousStableIdentity" or "Validated")
                        Notifications.Observe("identity." + device.Ip, explanation.IdentityState != "Validated", NotificationCategory.NewDevices,
                            NotificationSeverity.Warning, "Device identity conflict", "The Engine cannot select a unique device identity. Review address bindings before using device rules.", "Devices");
                }
                else LastError = L.T(read.Connection.Message);
            }
            catch { _effectiveObservedUtc = null; LastError = L.T("Engine effective policy could not be read."); }
            finally { _engineRequestPending = false; OnPropertyChanged(nameof(EngineEffectivePolicy)); OnPropertyChanged(nameof(EngineEffectivePolicyDiagnostics)); }
        }
        public ICommand RegisterSelectedDeviceCommand { get; }
        public ObservableCollection<DeviceDomainRuleVm> DeviceDomainRules { get; } = new();
        public Array OverrideStates => Enum.GetValues(typeof(DeviceDomainRuleState));
        public string SelectedDeviceSummary => SelectedDevice == null ? L.T("Select a device to review its policy.") :
            L.F("{0} · IP: {1} · MAC: {2}\n{3} device rules in the local draft; Engine address mapping is not verified.", SelectedDevice.DisplayName,
                SelectedDevice.Ip == "" ? L.T("unknown") : SelectedDevice.Ip, SelectedDevice.Mac == "" ? L.T("unknown") : SelectedDevice.Mac,
                _config.DeviceDomainPolicy.Overrides.Count(o => o.DeviceId == SelectedDevice.DeviceId && o.State != DeviceDomainRuleState.Inherit));
        public string SelectedDeviceDiagnostics => SelectedDevice?.IdentitySummary + "\n" + SelectedDevice?.LegacyPreference;

        private void RefreshDeviceDetail()
        {
            DeviceDomainRules.Clear();
            _effectiveObservedUtc = null;
            OnPropertyChanged(nameof(EngineEffectivePolicy)); OnPropertyChanged(nameof(EngineEffectivePolicyDiagnostics));
            OnPropertyChanged(nameof(SelectedDeviceSummary)); OnPropertyChanged(nameof(SelectedDeviceDiagnostics));
            if (SelectedDevice?.DeviceId is not Guid id) return;
            var names = Domains.Select(d => DomainName.Normalize(d.Domain)).Concat(_config.DeviceDomainPolicy.Overrides.Where(o => o.DeviceId == id).Select(o => o.Domain))
                .Where(d => d != "").Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
            foreach (var domain in names)
            {
                var state = _config.DeviceDomainPolicy.Overrides.FirstOrDefault(o => o.DeviceId == id && o.Domain == domain)?.State ?? DeviceDomainRuleState.Inherit;
                DeviceDomainRules.Add(new(domain, state, value =>
                {
                    var previous = _config.DeviceDomainPolicy;
                    var rules = previous.Overrides.Where(o => o.DeviceId != id || o.Domain != domain).ToImmutableArray();
                    _config.DeviceDomainPolicy = previous with { Overrides = rules.Add(new(id, domain, value)) };
                    try
                    {
                        _config.DeviceDomainPolicy = PolicyCanonicalization.Canonicalize(_config.DeviceDomainPolicy);
                        _configService.Save(_config);
                    }
                    catch { _config.DeviceDomainPolicy = previous; LastError = L.T("Override was not saved; previous selection retained."); ObserveDraftSaveFailure(true); return false; }
                    LastError = ""; ObserveDraftSaveFailure(false);
                    SafeLog(new ActivityEvent("WPF user action", "Policy", "Local device rule: {0}; {1}; {2} → {3}; Engine policy unchanged",
                        new[] { id.ToString(), domain, state.ToString(), value.ToString() }, Target: id + "/" + domain,
                        PreviousAction: state.ToString(), Action: value.ToString(), Outcome: "LocalDraftSaved"), "INFO");
                    _engineStatus.InvalidateSelection(); UpdateDnsEngineStatusText(); OnPropertyChanged(nameof(SelectedDeviceSummary)); OnPropertyChanged(nameof(SelectedDeviceDiagnostics));
                    return true;
                }, value => DraftEffective(id, domain, value)));
            }
        }

        private string DraftEffective(Guid id, string domain, DeviceDomainRuleState value)
        {
            var selected = _config.DeviceDomainPolicy.Overrides.Where(o => o.DeviceId == id &&
                (domain == o.Domain || domain.EndsWith("." + o.Domain, StringComparison.Ordinal))).OrderByDescending(o => o.Domain.Length).FirstOrDefault();
            var state = selected?.State ?? value;
            if (state != DeviceDomainRuleState.Inherit) return state == DeviceDomainRuleState.Block ? L.T("BLOCK (draft device rule)") : L.T("ALLOW (draft device rule)");
            var blocked = DomainPolicySelection.ForDns(_config.BlockedDomains).Any(d => domain == d || domain.EndsWith("." + d, StringComparison.Ordinal));
            return blocked ? L.T("BLOCK (global draft)") : L.T("ALLOW (global draft)");
        }

        private void RegisterSelectedDevice()
        {
            if (SelectedDevice is not { } device || device.DeviceId != null) return;
            var mac = DevicePolicyIdentity.NormalizeMac(device.Mac);
            if (mac == "" || Devices.Count(d => DevicePolicyIdentity.NormalizeMac(d.Mac) == mac) != 1 ||
                _config.DeviceDomainPolicy.Devices.Any(d => d.Mac == mac) ||
                _config.DevicePolicies.Count(d => DevicePolicyIdentity.NormalizeMac(d.Mac) == mac) > 1)
            { LastError = L.T("A unique observed MAC is required; ambiguous and IP-only entries need review."); return; }
            var id = Guid.NewGuid();
            var previous = _config.DeviceDomainPolicy;
            _config.DeviceDomainPolicy = previous with { Devices = previous.Devices.Add(new(id, device.DisplayName, mac, "windows-lan", "Explicit WPF registration from best-effort scan")) };
            try { _configService.Save(_config); device.DeviceId = id;
                Notifications.Observe("unknown." + (device.Mac == "" ? device.Ip : device.Mac), false, NotificationCategory.NewDevices,
                    NotificationSeverity.Warning, "", "", "Devices");
                _engineStatus.InvalidateSelection(); RefreshDeviceDetail(); UpdateDnsEngineStatusText(); }
            catch { _config.DeviceDomainPolicy = previous; LastError = L.T("Device registration was not saved."); }
        }

        private async void LoadFullPolicy()
        {
            if (_engineRequestPending) return;
            if (!LocalizedDialogs.Confirm(Application.Current?.MainWindow, L.T("Import Engine device policy and replace local device overrides? Local global domain choices are kept."),
                L.T("Read Engine device policy"))) return;
            _engineRequestPending = true; LastError = "";
            var generation = _engineSettingsGeneration;
            try
            {
                var read = await _dnsEngine.ReadFullPolicyAsync(_config.DnsEngine);
                if (generation != _engineSettingsGeneration) return;
                ObserveConnection(read.Connection);
                if (!read.Connection.Ok || read.Policy == null) { LastError = L.T(read.Connection.Message); ObservePolicyFailure(true); return; }
                _fullPolicyBaseline = read.Policy;
                // Read imports device policy only; local domain selections remain an explicit draft.
                _config.DeviceDomainPolicy = PolicyCanonicalization.Canonicalize(read.Policy.Policy);
                _configService.Save(_config);
                foreach (var registered in _config.DeviceDomainPolicy.Devices)
                    if (!Devices.Any(d => d.DeviceId == registered.DeviceId))
                        Devices.Add(new DeviceVm(new NetworkDevice { Mac = registered.Mac ?? "" }, registered.Name, false) { DeviceId = registered.DeviceId });
                RefreshDeviceDetail();
            }
            catch { LastError = L.T("Full policy could not be read; local draft not synchronized."); ObservePolicyFailure(true); }
            finally { _engineRequestPending = false; UpdateDnsEngineStatusText(); }
        }

        // ===================== DNS ENGINE ACTIONS =====================

        private void UpdateDnsEngineStatusText()
        {
            DnsEngineStatusText = L.F("Engine: {0} · Management: {1} · DNS: {2} · Filtering: {3} · Policy: {4} · Upstream: {5}",
                L.T(_engineStatus.EngineHost), L.T(_engineStatus.Management), L.T(_engineStatus.DnsService),
                L.T(_engineStatus.Filtering), L.T(_engineStatus.PolicyStatus), L.T(_engineStatus.Upstream));
            OnPropertyChanged(nameof(EngineEffectivePolicy)); OnPropertyChanged(nameof(EngineEffectivePolicyDiagnostics));
            OnPropertyChanged(nameof(EngineSafeModeText));
            OnPropertyChanged(nameof(EngineStatusDetailsText));
            (EnterEngineSafeModeCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (ExitEngineSafeModeCommand as RelayCommand)?.RaiseCanExecuteChanged();
        }

        public void OpenEngineSettings()
        {
            var dialog = new HostsGuardian.Wpf.EngineConnectionWindow(_config, _configService) { Owner = Application.Current.MainWindow };
            dialog.ShowDialog();
            _engineSettingsGeneration++;
            _engineStatus.Reset();
            _fullPolicyBaseline = null;
            _dnsEngineBaseUrl = _config.DnsEngine.BaseUrl;
            OnPropertyChanged(nameof(DnsEngineBaseUrl));
            OnPropertyChanged(nameof(EngineApiBaseUrl));
            UpdateDnsEngineStatusText();
        }

        private async void EnterEngineSafeMode() => await ChangeEngineSafeModeAsync(true);
        private async void ExitEngineSafeMode() => await ChangeEngineSafeModeAsync(false);

        private async Task ChangeEngineSafeModeAsync(bool enabled)
        {
            if (_engineRequestPending || !(enabled ? _engineStatus.CanEnterSafeMode : _engineStatus.CanExitSafeMode)) return;
            _engineRequestPending = true; LastError = "";
            var generation = _engineSettingsGeneration;
            _engineStatus.BeginRequest();
            UpdateDnsEngineStatusText();
            try
            {
                var transition = enabled
                    ? await _dnsEngine.EnterSafeModeAsync(_config.DnsEngine)
                    : await _dnsEngine.ExitSafeModeAsync(_config.DnsEngine);
                if (generation != _engineSettingsGeneration) return;
                _engineStatus.Complete(transition.Connection);
                ObserveConnection(transition.Connection);
                ObservePolicyFailure(!transition.Confirmed);
                if (!transition.Confirmed) LastError = L.T("Safe Mode transition unconfirmed: ") + L.T(transition.Connection.Message);
                SafeLog(transition.Confirmed ? L.T("Safe Mode transition confirmed by Engine status") :
                    L.T("Safe Mode transition unconfirmed: ") + L.T(transition.Connection.Message), transition.Confirmed ? "INFO" : "WARN");
            }
            catch
            {
                if (generation == _engineSettingsGeneration)
                {
                    _engineStatus.Complete(new(ConnectionState.NetworkFailure, L.T("Safe Mode request failed; current state unknown")));
                    LastError = L.T("Safe Mode request failed; current state unknown");
                    ObserveConnection(new(ConnectionState.NetworkFailure, LastError));
                }
            }
            finally { _engineRequestPending = false; UpdateDnsEngineStatusText(); RefreshActivity(); }
        }

        private async void TestDnsEngine()
        {
            if (_engineRequestPending) return;
            _engineRequestPending = true; LastError = "";
            var generation = _engineSettingsGeneration;
            _engineStatus.BeginRequest();
            UpdateDnsEngineStatusText();
            try
            {
                var result = await _dnsEngine.TestConnectionAsync(_config.DnsEngine);
                if (generation != _engineSettingsGeneration) return;
                _engineStatus.Complete(result);
                ObserveConnection(result);
                if (!result.Ok) LastError = L.T("DNS Engine test: ") + L.T(result.Message);
                SafeLog(L.T("DNS Engine test: ") + L.T(result.Message), result.Ok ? "INFO" : "WARN");
            }
            catch
            {
                if (generation == _engineSettingsGeneration)
                {
                    _engineStatus.Complete(new(ConnectionState.NetworkFailure, L.T("Connection failed")));
                    LastError = L.T("DNS Engine connection failed");
                    ObserveConnection(new(ConnectionState.NetworkFailure, LastError));
                }
            }
            finally { _engineRequestPending = false; UpdateDnsEngineStatusText(); RefreshActivity(); }
        }

        private async void PushDnsRules()
        {
            if (_engineRequestPending) return;
            _engineRequestPending = true; LastError = "";
            var generation = _engineSettingsGeneration;
            _engineStatus.BeginRequest();
            _engineStatus.InvalidateSelection();
            UpdateDnsEngineStatusText();
            try
            {
                var domains = DomainPolicySelection.ForDns(_config.BlockedDomains);
                _configService.Save(_config);
                if (_fullPolicyBaseline == null) { LastError = L.T("Read Engine device policy before sending the draft."); _engineStatus.Complete(new(ConnectionState.Incompatible, LastError)); ObservePolicyFailure(true); return; }
                var outgoing = PolicyCanonicalization.Canonicalize(_config.DeviceDomainPolicy with { GlobalBlockedDomains = domains.ToImmutableArray() });
                var confirmation = await _dnsEngine.ReplaceFullPolicyAsync(_config.DnsEngine, new(_fullPolicyBaseline.Revision, outgoing, _fullPolicyBaseline.InstanceId));
                if (generation != _engineSettingsGeneration) return;
                var selectionUnchanged = domains.SequenceEqual(DomainPolicySelection.ForDns(_config.BlockedDomains)) &&
                    System.Text.Json.JsonSerializer.Serialize(outgoing) == System.Text.Json.JsonSerializer.Serialize(
                        PolicyCanonicalization.Canonicalize(_config.DeviceDomainPolicy with { GlobalBlockedDomains = DomainPolicySelection.ForDns(_config.BlockedDomains).ToImmutableArray() }));
                _engineStatus.Complete(confirmation.Connection,
                    confirmation.Confirmed && selectionUnchanged ? confirmation.Readback?.Revision : null);
                ObserveConnection(confirmation.Connection);
                ObservePolicyFailure(!confirmation.Confirmed);
                if (confirmation.Confirmed && confirmation.Readback != null) _fullPolicyBaseline = confirmation.Readback;
                if (!confirmation.Confirmed) LastError = L.T("Push rules: ") + L.T(confirmation.Connection.Message);
                SafeLog(confirmation.Confirmed ? L.T("DNS policy revision confirmed") : L.T("DNS policy confirmation failed: ") + L.T(confirmation.Connection.Message),
                    confirmation.Confirmed ? "INFO" : "WARN");
            }
            catch
            {
                if (generation == _engineSettingsGeneration)
                {
                    _engineStatus.Complete(new(ConnectionState.EngineError, L.T("Policy request failed")));
                    LastError = L.T("DNS policy request failed; synchronization unknown");
                    ObservePolicyFailure(true);
                }
            }
            finally { _engineRequestPending = false; UpdateDnsEngineStatusText(); RefreshActivity(); }
        }

        // ===================== LOG COMMAND IMPLEMENTATIONS =====================

        private void CopySelectedLog()
        {
            try
            {
                LastError = "";
                if (SelectedLog == null) return;

                var text = $"{SelectedLog.Time} | {SelectedLog.Level} | {SelectedLog.DisplayMessage}";
                Clipboard.SetText(text);

                SafeLog(L.T("Selected log copied"), "INFO");
                RefreshActivity();
            }
            catch (Exception ex)
            {
                Fail(L.T("Copy selected log failed"), ex, level: "WARN");
            }
        }

        private void ClearLog()
        {
            try
            {
                LastError = "";
                LogItems.Clear();
                ActivityLines.Clear();
                SafeLog(L.T("Log cleared (UI only)"), "INFO");
            }
            catch (Exception ex)
            {
                Fail(L.T("Clear log failed"), ex, level: "WARN");
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

            OnPropertyChanged(nameof(RouterIp));
            OnPropertyChanged(nameof(EngineApiBaseUrl));
            OnPropertyChanged(nameof(EngineStatusText));
            OnPropertyChanged(nameof(RouterSummaryText));
            OnPropertyChanged(nameof(DevicesSummaryText));
        }

        // ===================== SAFE LOG / FAIL =====================

        private void SafeLog(ActivityEvent activity, string level) => SafeLog(activity.Serialize(), level);

        private void SafeLog(string message, string level)
        {
            try { _logService.Write(message, level); }
            catch { }
        }

        private void Fail(string title, Exception ex, string level = "ERROR")
        {
            LastError = $"{title}: {SecretRedactor.Clean(ex.Message)}";
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
