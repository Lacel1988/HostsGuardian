using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Automation;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Services;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

namespace HostsGuardian.Wpf;

/// <summary>Read-only authenticated product insight. No policy or system mutations.</summary>
public sealed class OperationsWorkspaceWindow : Window
{
    private readonly DnsEngineService _engine;
    private readonly DnsEngineConfig _config;
    private readonly NotificationCenter _notifications;
    private readonly Func<ConnectionResult, bool> _synchronized;
    private readonly TabControl _tabs = new();
    private readonly TextBox _health = new() { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly DataGrid _activity = Grid();
    private readonly DataGrid _usage = Grid();
    private readonly DataGrid _audit = Grid();
    private readonly Button _refresh = new();
    private long _cursor;
    private string? _instance;
    public OperationsWorkspaceWindow(DnsEngineService engine, DnsEngineConfig config, NotificationCenter notifications, Func<ConnectionResult, bool> synchronized)
    {
        ToolTipService.SetInitialShowDelay(this, 2500); ToolTipService.SetBetweenShowDelay(this, 0);
        _engine = engine; _config = config; _notifications = notifications; _synchronized = synchronized;
        Width = 1080; Height = 720; MinWidth = 850; MinHeight = 600;
        Resources = new ResourceDictionary { Source = new Uri("/HostsGuardian.Wpf;component/Styles/MatrixStyles.xaml", UriKind.Relative) };
        SetResourceReference(BackgroundProperty, "BgBrush");
        SetResourceReference(StyleProperty, typeof(Window));
        var root = new DockPanel { Margin = new Thickness(16) };
        var header = new StackPanel { Margin = new Thickness(0, 0, 0, 12) }; DockPanel.SetDock(header, Dock.Top);
        AutomationProperties.SetAutomationId(_refresh, "RefreshProductInsights");
        _refresh.Click += async (_, _) => await Refresh();
        header.Children.Add(_refresh); header.Children.Add(_status); root.Children.Add(header); root.Children.Add(_tabs);
        _tabs.Items.Add(new TabItem { Content = _health });
        var activityPanel = new DockPanel(); var note = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(6) };
        DockPanel.SetDock(note, Dock.Top); activityPanel.Children.Add(note);
        var rows = new System.Windows.Controls.Grid(); rows.RowDefinitions.Add(new()); rows.RowDefinitions.Add(new());
        rows.Children.Add(_activity); System.Windows.Controls.Grid.SetRow(_usage, 1); rows.Children.Add(_usage); activityPanel.Children.Add(rows);
        _tabs.Items.Add(new TabItem { Content = activityPanel }); _tabs.Items.Add(new TabItem { Content = _audit });
        Content = root;
        void Localize()
        {
            Title = L.T("Health, activity and policy audit"); AutomationProperties.SetName(this, Title); _refresh.Content = L.T("Check health and read insights"); _refresh.ToolTip = L.T("Reads Engine state without changing policy or network configuration."); ToolTipService.SetInitialShowDelay(_refresh, 2500);
            ((TabItem)_tabs.Items[0]).Header = L.T("Health"); ((TabItem)_tabs.Items[1]).Header = L.T("Activity and estimates"); ((TabItem)_tabs.Items[2]).Header = L.T("Policy audit");
            note.Text = L.T("DNS activity windows are estimates, not screen time. They never trigger blocking. Activity is memory-only: 24 hours, at most 256 buckets.");
            Columns(_activity, ("DeviceId", "DeviceId"), ("Service", "ServiceName"), ("UTC time window", "WindowStartUtc"), ("Allowed", "Allowed"), ("Blocked", "Blocked"), ("Failed", "Failed"), ("Ambiguous", "AmbiguousService"));
            Columns(_usage, ("DeviceId", "DeviceId"), ("Service", "ServiceName"), ("Active windows", "ActiveWindows"), ("Estimated activity minutes", "EstimatedActivityMinutes"), ("Evidence confidence", "Confidence"));
            Columns(_audit, ("UTC time", "AtUtc"), ("Operation", "Operation"), ("Actor evidence", "ActorEvidence"), ("Previous revision", "PreviousRevision"), ("Effective revision", "EffectiveRevision"), ("Outcome", "Outcome"), ("Changes", "Changes"), ("Policy SHA-256", "PolicyHash"));
        }
        Localize(); EventHandler changed = (_, _) => Localize(); L.Instance.LanguageChanged += changed;
        Closed += (_, _) => L.Instance.LanguageChanged -= changed;
    }
    private sealed record AuditRow(PolicyAuditRecord Record)
    {
        public DateTimeOffset AtUtc => Record.AtUtc;
        public string Operation => L.T(Record.Operation);
        public string ActorEvidence => L.T(Record.ActorEvidence);
        public long? PreviousRevision => Record.PreviousRevision;
        public long? EffectiveRevision => Record.EffectiveRevision;
        public string Outcome => L.T(Record.Outcome);
        public string Changes => string.Join("; ", Record.Changes.Split("; ").Select(L.T));
        public string PolicyHash => Record.PolicyHash;
    }
    private static DataGrid Grid() => new() { IsReadOnly = true, AutoGenerateColumns = false, CanUserAddRows = false, MinHeight = 130 };
    private static void Columns(DataGrid grid, params (string Label, string Property)[] columns)
    {
        grid.Columns.Clear();
        foreach (var column in columns) grid.Columns.Add(new DataGridTextColumn { Header = L.T(column.Label), Binding = new Binding(column.Property), MinWidth = 90, Width = DataGridLength.SizeToCells });
    }
    private async Task Refresh()
    {
        _refresh.IsEnabled = false; _status.Text = L.T("Reading authenticated Engine evidence...");
        try
        {
            var result = await _engine.TestConnectionAsync(_config);
            _health.Text = HealthSummary.Export(result, _synchronized(result));
            if (!result.Ok) { _activity.ItemsSource = null; _usage.ItemsSource = null; _audit.ItemsSource = null; _status.Text = L.T(result.Message); return; }
            var activity = await _engine.ReadActivityAsync(_config);
            _activity.ItemsSource = activity.Activity?.Buckets;
            _usage.ItemsSource = activity.Activity == null ? null : UsageEstimation.Estimate(activity.Activity);
            var audit = await _engine.ReadPolicyAuditAsync(_config);
            _audit.ItemsSource = audit.Audit?.Entries.OrderByDescending(r => r.AtUtc).Select(r => new AuditRow(r)).ToArray();
            var events = await _engine.ReadOperationalEventsAsync(_config, _cursor);
            if (events.Batch is { } batch)
            {
                if (_instance != null && _instance != batch.InstanceId) _cursor = 0;
                _instance = batch.InstanceId; _cursor = batch.LatestSequence;
                OperationalNotificationObserver.Observe(_notifications, batch);
            }
            _status.Text = activity.Activity != null && audit.Audit?.Available == true
                ? L.T("Current read-only insights received. No policy was delivered.")
                : L.T("Some insights are unavailable on this Engine version. Unknown is not zero activity or an empty audit.");
        }
        catch { _status.Text = L.T("Engine insights could not be read."); _activity.ItemsSource = null; _usage.ItemsSource = null; _audit.ItemsSource = null; }
        finally { _refresh.IsEnabled = true; }
    }
}
