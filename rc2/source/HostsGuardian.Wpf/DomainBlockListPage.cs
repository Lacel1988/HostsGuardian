using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Automation;
using System.Windows.Media;
using System.Windows.Input;
using System.Windows.Threading;
using DesignPrototype.Engine;

namespace DesignPrototype;

public sealed partial class PrototypeWindow
{
    Guid? blockListScope;
    string blockListSearch = "";
    int blockListEpoch;
    DispatcherTimer? blockListTimer;

    void BuildDomainBlockList()
    {
        int epoch = ++blockListEpoch;
        blockListTimer?.Stop();
        var full = Json.P(EngineData.Value("/v2/policy"), "policy");
        var scopes = new List<KeyValuePair<Guid?, string>>();
        if (userSession?.Role != "Operator") scopes.Add(new(null, "Minden eszköz · globális lista"));
        foreach (var d in Json.A(full, "devices"))
            if (Guid.TryParse(Json.S(d, "deviceId"), out var id)) scopes.Add(new(id, Json.S(d, "name") ?? "Eszköz"));
        if (!scopes.Any(s => s.Key == blockListScope)) blockListScope = scopes.FirstOrDefault().Key;
        var scope = new ComboBox { ItemsSource = scopes, DisplayMemberPath = "Value", SelectedItem = scopes.FirstOrDefault(s => s.Key == blockListScope), MinWidth = 220 };
        AutomationProperties.SetAutomationId(scope, "BlockListScope");
        var search = Input(blockListSearch, "BlockListSearch");
        var domain = Input("", "BlockListDomain");
        var feedback = Ui.Text("Engine-lista betöltése…", 13);
        AutomationProperties.SetAutomationId(feedback, "BlockListFeedback");
        var rows = new StackPanel();
        JsonElement? snapshot = null;
        DateTimeOffset loadedAt = DateTimeOffset.MinValue;
        DateTimeOffset attemptedAt = DateTimeOffset.MinValue;
        bool busy = false;
        bool reading = false;
        Button? add = null;
        var controls = new List<ButtonBase>();
        bool staleShown = false;
        string PathForScope() => "/v1/access/block-list" + (blockListScope is Guid id ? "?deviceId=" + id : "");
        bool Fresh() => snapshot.HasValue && DateTimeOffset.UtcNow - loadedAt < TimeSpan.FromSeconds(30) && BackendSessionActive;
        void EnableControls() { if(add != null) add.IsEnabled = (!busy || reading) && Fresh() && CanChangeRules; foreach (var b in controls) b.IsEnabled = (!busy || reading) && Fresh() && CanChangeRules; }

        void Render()
        {
            string? focusedId = Keyboard.FocusedElement is FrameworkElement focused ? AutomationProperties.GetAutomationId(focused) : null;
            rows.Children.Clear(); controls.Clear();
            if (snapshot == null) return;
            foreach (var r in Json.A(snapshot, "rows").Where(r => (Json.S(r, "domain") ?? "").Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase)))
            {
                string name = Json.S(r, "domain") ?? "";
                bool configured = Json.B(r, "configuredBlocked") == true, blocked = Json.B(r, "effectiveBlocked") == true;
                bool known = Json.B(r, "decisionKnown") == true;
                bool saved = Json.B(r, "saved") == true, legacy = Json.B(r, "legacyAllow") == true;
                string reason = Json.S(r, "reason") ?? "";
                var layout = new Grid(); layout.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
                layout.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
                var label = Ui.Stack(Ui.Text(name, 17, bold: true),
                    Ui.Text(!Fresh() ? "Állapot nem igazolt · frissítés szükséges" : !known ? "Érvényesülés nem igazolt · nincs validált eszközkötés" : blocked ? (reason == "GlobalBlock" && blockListScope.HasValue ? "● Globálisan tiltva" : "● Tiltva · Engine-döntés") : "● Nincs érvényes blokkolás", 14, !Fresh() || !known ? "#B6C6DA" : blocked ? "#FF9B9B" : "#71E2AD"),
                    Ui.Text((configured ? "Saját tiltás bekapcsolva" : saved ? "Mentve · saját tiltás kikapcsolva" : "Globális listából megjelenítve") + (legacy ? " · Korábbi engedélyezési kivétel" : ""), 12),
                    Ui.Text(blockListScope.HasValue ? (known ? "Eszközazonosítás: validált · DNS-hatás: nem igazolt" : "Eszközazonosítás és DNS-hatás: nem igazolt") : "Kliensenkénti DNS-hatás: külön ellenőrizendő", 12));
                foreach (var text in label.Children.OfType<TextBlock>()) text.TextWrapping = TextWrapping.Wrap;
                layout.Children.Add(label);
                var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                var toggle = new ToggleButton { IsChecked = configured, Content = configured ? "Bekapcsolva" : "Kikapcsolva", Style = (Style)Application.Current.FindResource("BlockListSwitch"), Margin = new Thickness(8, 0, 8, 0) };
                AutomationProperties.SetAutomationId(toggle, "ToggleBlock_" + name);
                AutomationProperties.SetName(toggle, name + " saját tiltás");
                toggle.Click += async (_, _) => { toggle.IsChecked = configured; await Change(name, !configured, false); };
                toggle.ToolTip = configured ? "Saját tiltás kikapcsolása; más érvényes tiltás megmaradhat." : "Tiltás bekapcsolása a kiválasztott hatókörben.";
                actions.Children.Add(toggle); controls.Add(toggle);
                if (saved)
                {
                    var remove = Ui.Button("Törlés", () => Modal("Domain eltávolítása", Ui.Stack(Ui.Text(name + " – a kiválasztott hatókör saját szabálya is megszűnik. Más hatókör tiltása megmaradhat."), Actions(("Eltávolítom", async () => { CloseModal(); await Change(name, false, true); }, "DeleteSavedDomain")))), "DeleteBlock_" + name);
                    actions.Children.Add(remove); controls.Add(remove);
                }
                Grid.SetColumn(actions, 1); layout.Children.Add(actions);
                var card = Ui.Card(layout); card.Padding = new Thickness(14,10,14,10); rows.Children.Add(card);
            }
            if (rows.Children.Count == 0) rows.Children.Add(Ui.Text("Nincs a keresésnek megfelelő domain."));
            EnableControls();
            if(!string.IsNullOrEmpty(focusedId)) controls.FirstOrDefault(b => AutomationProperties.GetAutomationId(b) == focusedId)?.Focus();
        }
        async Task Load()
        {
            if (busy || epoch != blockListEpoch) return;
            busy = true; reading = true; attemptedAt = DateTimeOffset.UtcNow; feedback.Text = "Engine-állapot frissítése…"; EnableControls();
            try
            {
                var value = await userSession!.Call(PathForScope());
                if (epoch != blockListEpoch) return;
                if (value == null || !value.Value.TryGetProperty("rows", out _) || Json.N(value, "revision") == null) throw new InvalidOperationException("Nem igazolt listaformátum.");
                snapshot = value; staleShown = false; loadedAt = DateTimeOffset.UtcNow;
                feedback.Text = "Engine visszaigazolva · revízió " + Json.N(snapshot, "revision") + " · " + loadedAt.ToLocalTime().ToString("HH:mm:ss") + " · a DNS-hatás külön bizonyítandó";
            }
            catch (Exception e) { snapshot = null; loadedAt = DateTimeOffset.MinValue; feedback.Text = "A lista nem igazolható. Ehhez a felülethez a Block List API-t támogató izolált Engine szükséges. " + (e is InvalidOperationException ? e.Message : "Kapcsolati hiba."); }
            finally { busy = false; reading = false; if (epoch == blockListEpoch) Render(); }
        }
        async Task Change(string name, bool enabled, bool delete)
        {
            if (busy || !Fresh() || !CanChangeRules || epoch != blockListEpoch) return;
            var read = snapshot!.Value;
            busy = true; EnableControls();
            try
            {
                var result = await userSession!.Call(PathForScope(), new { expectedInstanceId = Json.S(read, "instanceId"), expectedRevision = Json.N(read, "revision"), domain = name, enabled, delete });
                if (result == null || Json.B(result, "ok") != true) throw new InvalidOperationException("Nincs igazolt mentés.");
                loadedAt = DateTimeOffset.MinValue;
                feedback.Text = "Mentés fogadva; friss Engine-visszaolvasás szükséges.";
            }
            catch (Exception e) { loadedAt = DateTimeOffset.MinValue; feedback.Text = "Nem igazolt módosítás. " + (e is InvalidOperationException ? e.Message : "Kapcsolati hiba."); busy = false; Render(); return; }
            busy = false;
            await Load();
            if (epoch == blockListEpoch && Fresh())
            {
                if (delete) domain.Focus();
                else rows.Children.OfType<Border>().SelectMany(b => Descendants(b).OfType<ToggleButton>()).FirstOrDefault(b => AutomationProperties.GetAutomationId(b) == "ToggleBlock_" + name)?.Focus();
            }
        }
        add = Ui.Button("Domain hozzáadása", async () => { var name = HostsGuardian.Core.Models.DomainName.Normalize(domain.Text); if (name.Length == 0) { feedback.Text = "Adj meg érvényes domainnevet."; return; } await Change(name, true, false); }, "AddBlockDomain");
        var toolbar = new Grid();
        toolbar.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        toolbar.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        toolbar.RowDefinitions.Add(new() { Height = GridLength.Auto }); toolbar.RowDefinitions.Add(new() { Height = GridLength.Auto });
        var scopeField = Field("Hatókör", scope); scopeField.Margin = new Thickness(0,0,12,6); toolbar.Children.Add(scopeField);
        var searchField = Field("Keresés", search); Grid.SetColumn(searchField, 1); toolbar.Children.Add(searchField);
        var newField = Field("Új domain", domain); newField.Margin = new Thickness(0,0,12,0); Grid.SetRow(newField, 1); toolbar.Children.Add(newField);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Bottom };
        buttons.Children.Add(add); buttons.Children.Add(Ui.Button("Frissítés", async () => await Load(), "RefreshBlockList"));
        Grid.SetColumn(buttons, 1); Grid.SetRow(buttons, 1); toolbar.Children.Add(buttons);
        page.Children.Add(Ui.Card(Ui.Stack(toolbar, feedback)));
        page.Children.Add(rows);
        scope.SelectionChanged += (_, _) => { if (scope.SelectedItem is KeyValuePair<Guid?, string> choice) { blockListScope = choice.Key; BuildPage(); } };
        search.TextChanged += (_, _) => { blockListSearch = search.Text; Render(); };
        // Add is outside the row list, so keep its availability independent of filtering.
        blockListTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        blockListTimer.Tick += (_, _) => { if (epoch != blockListEpoch || CurrentView != "Domainek és policy") { blockListTimer?.Stop(); return; } add.IsEnabled = (!busy || reading) && Fresh() && CanChangeRules; if (!busy && BackendSessionActive && DateTimeOffset.UtcNow - attemptedAt >= TimeSpan.FromSeconds(20)) _ = Load(); if (!Fresh() && snapshot != null && !staleShown) { staleShown = true; Render(); } };
        blockListTimer.Start(); add.IsEnabled = false;
        _ = Load();
    }
}
