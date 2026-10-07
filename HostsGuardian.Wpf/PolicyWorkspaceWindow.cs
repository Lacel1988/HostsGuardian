using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using Microsoft.Win32;
using L = HostsGuardian.Wpf.Localization.LocalizationService;
using HostsGuardian.Wpf.Services;

namespace HostsGuardian.Wpf;

/// <summary>Explicit GUI authoring of a local draft. Never contacts an Engine.</summary>
public sealed class PolicyWorkspaceWindow : Window
{
    private readonly PolicyDraftSession _session;
    private FullDnsPolicy _draft { get => _session.Policy; set => _session.Replace(value); }
    private readonly FullDnsPolicy _before;
    private readonly Action<FullDnsPolicy> _save;
    private readonly TabControl _tabs = new();
    private readonly TextBox _evidence = new() { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MinHeight = 100 };
    public PolicyWorkspaceWindow(FullDnsPolicy policy, Action<FullDnsPolicy> save)
    {
        ToolTipService.SetInitialShowDelay(this, 2500); ToolTipService.SetBetweenShowDelay(this, 0);
        _before = PolicyCanonicalization.Canonicalize(policy);
        _session = new PolicyDraftSession(_before); _save = save;
        Title = L.T("Policy workspace"); System.Windows.Automation.AutomationProperties.SetName(this, Title); Width = 1050; Height = 720; MinWidth = 850; MinHeight = 600;
        SetResourceReference(BackgroundProperty, "BgBrush");
        SetResourceReference(StyleProperty, typeof(Window));
        Resources = new ResourceDictionary { Source = new Uri("/HostsGuardian.Wpf;component/Styles/MatrixStyles.xaml", UriKind.Relative) };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var actions = new WrapPanel(); DockPanel.SetDock(actions, Dock.Top); panel.Children.Add(actions);
        Button(actions, "Preview draft", () => _evidence.Text = PolicyBackup.Preview(_before, _draft, (template, values) => L.F(template, values)));
        Button(actions, "Save local draft", () =>
        {
            _draft = PolicyCanonicalization.Canonicalize(_draft); _evidence.Text = PolicyBackup.Preview(_before, _draft, (template, values) => L.F(template, values));
            if (LocalizedDialogs.Confirm(this, _evidence.Text, L.T("Save local draft"))) { _save(_draft); DialogResult = true; }
        });
        Button(actions, "Policy backup", () =>
        {
            var dialog = new SaveFileDialog { Filter = "HostsGuardian policy backup|*.json", FileName = "hostsguardian-policy-backup.json" };
            if (dialog.ShowDialog(this) == true) File.WriteAllText(dialog.FileName, PolicyBackup.Export(_draft));
        });
        Button(actions, "Restore to draft", () =>
        {
            var dialog = new OpenFileDialog { Filter = "HostsGuardian policy backup|*.json" };
            if (dialog.ShowDialog(this) != true) return;
            if (new FileInfo(dialog.FileName).Length > 1048576) throw new ArgumentException("Backup exceeds size limit");
            var restored = PolicyBackup.Import(File.ReadAllText(dialog.FileName));
            var preview = PolicyBackup.Preview(_draft, restored, (template, values) => L.F(template, values));
            if (LocalizedDialogs.Confirm(this, preview, L.T("Restore to draft"))) { _draft = restored; Rebuild(); _evidence.Text = preview; }
        });
        DockPanel.SetDock(_evidence, Dock.Bottom); panel.Children.Add(_evidence); panel.Children.Add(_tabs);
        Content = panel; Rebuild();
    }
    private void Button(Panel panel, string label, Action action)
    {
        var button = new Button { Content = L.T(label), Margin = new Thickness(4), Padding = new Thickness(10, 5, 10, 5) };
        System.Windows.Automation.AutomationProperties.SetAutomationId(button, label.Replace(" ", ""));
        if (label is "Save local draft" or "Restore to draft") button.ToolTip = L.T("This changes only the local draft; Engine delivery is separate.");
        if (label == "Policy backup") button.ToolTip = L.T("Exports policy only; no credentials or certificates.");
        ToolTipService.SetInitialShowDelay(button, 2500); ToolTipService.SetBetweenShowDelay(button, 0);
        button.Click += (_, _) => { try { action(); } catch (Exception e) { LocalizedDialogs.Show(e.Message, L.T("Policy draft rejected")); } };
        panel.Children.Add(button);
    }
    private StackPanel Page(string title)
    {
        var panel = new StackPanel { Margin = new Thickness(12) };
        System.Windows.Automation.AutomationProperties.SetAutomationId(panel, title.Replace(" ", ""));
        _tabs.Items.Add(new TabItem { Header = L.T(title), Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });
        return panel;
    }
    private static TextBox Field(Panel panel, string label, string value = "")
    { panel.Children.Add(new TextBlock { Text = L.T(label), Margin = new Thickness(0, 8, 0, 3) }); var input = new TextBox { Text = value, MinHeight = 28 }; System.Windows.Automation.AutomationProperties.SetAutomationId(input, "Field" + label.Replace(" ", "")); panel.Children.Add(input); return input; }
    private ListBox Devices(Panel panel, IEnumerable<Guid>? selected = null)
    {
        panel.Children.Add(new TextBlock { Text = L.T("Devices") });
        var list = new ListBox { ItemsSource = _draft.Devices, DisplayMemberPath = "Name", SelectionMode = SelectionMode.Multiple, Height = 90 };
        panel.Children.Add(list);
        foreach (var item in _draft.Devices.Where(d => selected?.Contains(d.DeviceId) == true)) list.SelectedItems.Add(item);
        return list;
    }
    private void Upgrade() => _draft = _draft with { SchemaVersion = 3, Program = _draft.Program ?? PolicyProgram.Empty };
    private void Rebuild()
    {
        _tabs.Items.Clear(); Identity(); Groups(); Services(); Profiles(); Schedules(); Explain();
    }
    private void Identity()
    {
        var panel = Page("Device identity");
        var selected = new ComboBox { ItemsSource = _draft.Devices, DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(selected);
        var alias = Field(panel, "Alias"); var owner = Field(panel, "Owner");
        panel.Children.Add(new TextBlock {Text=L.T("Device type")});
        var type=new ComboBox {ItemsSource=new[]{new HostsGuardian.Wpf.ViewModels.DeviceTypeChoiceVm("")}.Concat(DeviceTypes.All.Select(t=>new HostsGuardian.Wpf.ViewModels.DeviceTypeChoiceVm(t.Id))).ToArray(),ItemTemplate=HostsGuardian.Wpf.ViewModels.DeviceTypeChoiceVm.LabelTemplate(),SelectedValuePath="Id",MinHeight=30};panel.Children.Add(type);
        var loadingType = false; var typeChanged = false;
        type.SelectionChanged += (_, _) => { if (!loadingType) typeChanged = true; };
        var location = Field(panel, "Location");
        var identity = new TextBlock { TextWrapping = TextWrapping.Wrap }; panel.Children.Add(identity);
        selected.SelectionChanged += (_, _) =>
        {
            if (selected.SelectedItem is not DeviceRegistration d) return;
            loadingType = true; typeChanged = false;
            alias.Text = d.Metadata?.Alias ?? ""; owner.Text = d.Metadata?.Owner ?? ""; type.SelectedValue = DeviceTypes.Find(d.Metadata?.Type)?.Id ?? ""; location.Text = d.Metadata?.Location ?? ""; loadingType = false;
            identity.Text = $"DeviceId: {d.DeviceId}\nMAC: {d.Mac ?? L.T("unknown")}\n{d.Scope}; {d.Provenance}";
        };
        Button(panel, "Save metadata", () =>
        {
            if (selected.SelectedItem is not DeviceRegistration d) return;
            var previous = _draft; Upgrade(); try { _draft = _draft with { Devices = _draft.Devices.Select(x => x.DeviceId == d.DeviceId ? x with { Metadata = new(alias.Text, owner.Text, typeChanged ? type.SelectedValue as string ?? "" : d.Metadata?.Type ?? "", location.Text) } : x).ToImmutableArray() };
            _draft = PolicyCanonicalization.Canonicalize(_draft); } catch { _draft = previous; throw; } Rebuild();
        });
    }
    private ObservableCollection<RuleRow> Rules(Panel panel)
    {
        panel.Children.Add(new TextBlock { Text = L.T("Rules: use a domain OR a service, never both. Inherit makes no decision."), TextWrapping = TextWrapping.Wrap });
        var rows = new ObservableCollection<RuleRow>();
        var grid = new DataGrid { ItemsSource = rows, AutoGenerateColumns = false, Height = 180, CanUserAddRows = true, CanUserDeleteRows = true };
        grid.Columns.Add(new DataGridTextColumn { Header = L.T("Domain"), Binding = new System.Windows.Data.Binding(nameof(RuleRow.Domain)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        grid.Columns.Add(new DataGridComboBoxColumn { Header = L.T("Service"), ItemsSource = (_draft.Program?.Services ?? []), DisplayMemberPath = "Name", SelectedValuePath = "ServiceId", SelectedValueBinding = new System.Windows.Data.Binding(nameof(RuleRow.ServiceId)) });
        var stateStyle = new Style(typeof(ComboBox)); stateStyle.Setters.Add(new Setter(ItemsControl.ItemTemplateProperty, LocalizedEnumTemplate.Create()));
        grid.Columns.Add(new DataGridComboBoxColumn { ElementStyle = stateStyle, EditingElementStyle = stateStyle, Header = L.T("State"), ItemsSource = Enum.GetValues<DeviceDomainRuleState>(), SelectedItemBinding = new System.Windows.Data.Binding(nameof(RuleRow.State)) });
        panel.Children.Add(grid); return rows;
    }
    private void Groups()
    {
        var panel = Page("Device groups"); var groups = _draft.Program?.Groups ?? [];
        var selected = new ComboBox { ItemsSource = groups, DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(selected);
        var name = Field(panel, "Name"); var devices = Devices(panel); var rules = Rules(panel);
        selected.SelectionChanged += (_, _) => { if (selected.SelectedItem is not DeviceGroup g) return; name.Text = g.Name; devices.SelectedItems.Clear(); foreach (var d in _draft.Devices.Where(d => g.DeviceIds.Contains(d.DeviceId))) devices.SelectedItems.Add(d); LoadRules(rules, g.Rules); };
        Button(panel, "New", () => { selected.SelectedItem = null; name.Text = ""; devices.SelectedItems.Clear(); rules.Clear(); });
        Button(panel, "Save group", () =>
        {
            Upgrade(); var id = (selected.SelectedItem as DeviceGroup)?.GroupId ?? Guid.NewGuid();
            var item = new DeviceGroup(id, name.Text, devices.SelectedItems.Cast<DeviceRegistration>().Select(d => d.DeviceId).ToImmutableArray(), ReadRules(rules));
            var previous = _draft; try { _draft = _draft with { Program = _draft.Program! with { Groups = _draft.Program.Groups.Where(g => g.GroupId != id).Append(item).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); } catch { _draft = previous; throw; }
            Rebuild();
        });
        Button(panel, "Remove selected", () => { if (selected.SelectedItem is not DeviceGroup g) return; var previous = _draft; try { _draft = _draft with { Program = _draft.Program! with { Groups = groups.Where(x => x.GroupId != g.GroupId).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); } catch { _draft = previous; throw; } Rebuild(); });
    }
    private void Services()
    {
        var panel = Page("Service catalog"); var selected = new ComboBox { ItemsSource = _draft.Program?.Services ?? [], DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(selected);
        var name = Field(panel, "Name"); var revision = Field(panel, "Definition revision"); var domains = Field(panel, "Domains (one per line)"); domains.AcceptsReturn = true; domains.Height = 160;
        selected.SelectionChanged += (_, _) => { if (selected.SelectedItem is not CatalogService s) return; name.Text = s.Name; revision.Text = s.DefinitionRevision; domains.Text = string.Join(Environment.NewLine, s.Domains); };
        panel.Children.Add(new TextBlock { Text = L.T("Catalog entries do not block anything until a user adds a rule. DNS cannot identify exact application usage."), TextWrapping = TextWrapping.Wrap });
        Button(panel, "New", () => { selected.SelectedItem = null; name.Text = ""; revision.Text = ""; domains.Text = ""; });
        Button(panel, "Save service", () => { Upgrade(); var id = (selected.SelectedItem as CatalogService)?.ServiceId ?? Guid.NewGuid(); var item = new CatalogService(id, name.Text, revision.Text, domains.Text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).ToImmutableArray()); var previous = _draft; try { _draft = _draft with { Program = _draft.Program! with { Services = _draft.Program.Services.Where(s => s.ServiceId != id).Append(item).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); } catch { _draft = previous; throw; } Rebuild(); });
        Button(panel, "Remove selected", () =>
        {
            if (selected.SelectedItem is not CatalogService selectedDefinition) return;
            var previous = _draft;
            try { _draft = _draft with { Program = _draft.Program! with { Services = _draft.Program.Services.Where(x => x.ServiceId != selectedDefinition.ServiceId).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); }
            catch { _draft = previous; throw; }
            Rebuild();
        });
    }
    private void Profiles()
    {
        var panel = Page("Profiles"); var selected = new ComboBox { ItemsSource = _draft.Program?.Profiles ?? [], DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(selected);
        var name = Field(panel, "Name"); var enabled = new CheckBox { Content = L.T("Enabled") }; var always = new CheckBox { Content = L.T("Always active") }; var global = new CheckBox { Content = L.T("Applies globally") }; panel.Children.Add(enabled); panel.Children.Add(always); panel.Children.Add(global);
        var devices = Devices(panel); var groups = new ListBox { ItemsSource = _draft.Program?.Groups ?? [], DisplayMemberPath = "Name", SelectionMode = SelectionMode.Multiple, Height = 80 }; panel.Children.Add(groups); var rules = Rules(panel);
        selected.SelectionChanged += (_, _) => { if (selected.SelectedItem is not PolicyProfile p) return; name.Text = p.Name; enabled.IsChecked = p.Enabled; always.IsChecked = p.AlwaysActive; global.IsChecked = p.AppliesGlobally; devices.SelectedItems.Clear(); groups.SelectedItems.Clear(); foreach (var d in _draft.Devices.Where(d => p.DeviceIds.Contains(d.DeviceId))) devices.SelectedItems.Add(d); foreach (var g in _draft.Program!.Groups.Where(g => p.GroupIds.Contains(g.GroupId))) groups.SelectedItems.Add(g); LoadRules(rules, p.Rules); };
        Button(panel, "New", () => { selected.SelectedItem = null; name.Text = ""; enabled.IsChecked = false; always.IsChecked = false; global.IsChecked = false; devices.SelectedItems.Clear(); groups.SelectedItems.Clear(); rules.Clear(); });
        Button(panel, "Save profile", () => { Upgrade(); var id = (selected.SelectedItem as PolicyProfile)?.ProfileId ?? Guid.NewGuid(); var item = new PolicyProfile(id, name.Text, enabled.IsChecked == true, always.IsChecked == true, global.IsChecked == true, devices.SelectedItems.Cast<DeviceRegistration>().Select(d => d.DeviceId).ToImmutableArray(), groups.SelectedItems.Cast<DeviceGroup>().Select(g => g.GroupId).ToImmutableArray(), ReadRules(rules)); var previous = _draft; try { _draft = _draft with { Program = _draft.Program! with { Profiles = _draft.Program.Profiles.Where(p => p.ProfileId != id).Append(item).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); } catch { _draft = previous; throw; } Rebuild(); });
        Button(panel, "Remove selected", () =>
        {
            if (selected.SelectedItem is not PolicyProfile selectedDefinition) return;
            var previous = _draft;
            try { _draft = _draft with { Program = _draft.Program! with { Profiles = _draft.Program.Profiles.Where(x => x.ProfileId != selectedDefinition.ProfileId).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); }
            catch { _draft = previous; throw; }
            Rebuild();
        });
    }
    private void Schedules()
    {
        var panel = Page("Schedules"); var selected = new ComboBox { ItemsSource = _draft.Program?.Schedules ?? [], DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(selected);
        var name = Field(panel, "Name"); var profile = new ComboBox { ItemsSource = _draft.Program?.Profiles ?? [], DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(profile);
        var enabled = new CheckBox { Content = L.T("Enabled") }; panel.Children.Add(enabled);
        var zone = Field(panel, "Time zone (IANA)", "Etc/UTC"); var start = Field(panel, "Start (HH:mm)", "22:00"); var end = Field(panel, "End (HH:mm)", "06:00");
        var days = new ListBox { ItemTemplate = LocalizedEnumTemplate.Create(), ItemsSource = Enum.GetValues<DayOfWeek>(), SelectionMode = SelectionMode.Multiple, Height = 110 }; panel.Children.Add(days);
        selected.SelectionChanged += (_, _) => { if (selected.SelectedItem is not PolicySchedule s) return; name.Text = s.Name; profile.SelectedItem = _draft.Program!.Profiles.FirstOrDefault(p => p.ProfileId == s.ProfileId); enabled.IsChecked = s.Enabled; zone.Text = s.TimeZoneId; start.Text = $"{s.StartMinute / 60:00}:{s.StartMinute % 60:00}"; end.Text = $"{s.EndMinute / 60:00}:{s.EndMinute % 60:00}"; days.SelectedItems.Clear(); foreach (var d in s.Days) days.SelectedItems.Add(d); };
        Button(panel, "New", () => { selected.SelectedItem = null; name.Text = ""; enabled.IsChecked = false; days.SelectedItems.Clear(); });
        Button(panel, "Save schedule", () => { if (profile.SelectedItem is not PolicyProfile p) throw new ArgumentException(L.T("Select a profile")); int Minute(string value) { var t = TimeSpan.ParseExact(value, @"hh\:mm", System.Globalization.CultureInfo.InvariantCulture); return (int)t.TotalMinutes; } Upgrade(); var id = (selected.SelectedItem as PolicySchedule)?.ScheduleId ?? Guid.NewGuid(); var item = new PolicySchedule(id, p.ProfileId, name.Text, enabled.IsChecked == true, zone.Text, days.SelectedItems.Cast<DayOfWeek>().ToImmutableArray(), Minute(start.Text), Minute(end.Text)); var previous = _draft; try { _draft = _draft with { Program = _draft.Program! with { Schedules = _draft.Program.Schedules.Where(s => s.ScheduleId != id).Append(item).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); } catch { _draft = previous; throw; } Rebuild(); });
        Button(panel, "Remove selected", () =>
        {
            if (selected.SelectedItem is not PolicySchedule selectedDefinition) return;
            var previous = _draft;
            try { _draft = _draft with { Program = _draft.Program! with { Schedules = _draft.Program.Schedules.Where(x => x.ScheduleId != selectedDefinition.ScheduleId).ToImmutableArray() } }; _draft = PolicyCanonicalization.Canonicalize(_draft); }
            catch { _draft = previous; throw; }
            Rebuild();
        });
    }
    private void Explain()
    {
        var panel = Page("Why blocked? / Preview"); var device = new ComboBox { ItemsSource = _draft.Devices, DisplayMemberPath = "Name", MinHeight = 30 }; panel.Children.Add(device);
        var domain = Field(panel, "Domain"); var time = Field(panel, "UTC time (ISO 8601)", DateTimeOffset.UtcNow.ToString("O"));
        panel.Children.Add(new TextBlock { Text = L.T("Device override > Active Profile/Schedule > Device Group > Global. Same-layer Block wins. Preview is not Engine readback."), TextWrapping = TextWrapping.Wrap });
        Button(panel, "Explain draft decision", () => { var name = DomainName.Normalize(domain.Text); if (name == "") throw new ArgumentException(L.T("Invalid domain")); var result = PolicyDecision.Explain(PolicyCanonicalization.Canonicalize(_draft), (device.SelectedItem as DeviceRegistration)?.DeviceId, name, DateTimeOffset.Parse(time.Text, System.Globalization.CultureInfo.InvariantCulture)); _evidence.Text = DecisionEvidencePresentation.Format(result.Chain); });
    }
    public sealed class RuleRow
    { public Guid RuleId { get; set; } = Guid.NewGuid(); public string Domain { get; set; } = ""; public Guid? ServiceId { get; set; } public DeviceDomainRuleState State { get; set; } = DeviceDomainRuleState.Inherit; }
    private static void LoadRules(ObservableCollection<RuleRow> rows, ImmutableArray<ProgramRule> rules)
    { rows.Clear(); foreach (var r in rules) rows.Add(new() { RuleId = r.RuleId, Domain = r.Domain ?? "", ServiceId = r.ServiceId, State = r.State }); }
    private static ImmutableArray<ProgramRule> ReadRules(ObservableCollection<RuleRow> rows)
        => rows.Select(r => new ProgramRule(r.RuleId, string.IsNullOrWhiteSpace(r.Domain) ? null : r.Domain, r.ServiceId, r.State)).ToImmutableArray();
}
