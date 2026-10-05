using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using HostsGuardian.Core.Models;
using HostsGuardian.Wpf.ViewModels;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try { return Run(args); }
        catch (Exception exception) { Console.Error.WriteLine(exception); return 1; }
        finally { Application.Current?.Shutdown(); }
    }
    private static int Run(string[] args)
    {
        var domain = new DomainEntry { Domain = "fixture.invalid" };
        var changes = 0;
        domain.PropertyChanged += (_, args) => { if (args.PropertyName == "DnsBlocked") changes++; };
        var checkbox = new CheckBox();
        BindingOperations.SetBinding(checkbox, System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty,
            new Binding(nameof(DomainEntry.DnsBlocked)) { Source = domain, Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        checkbox.IsChecked = true;
        if (!domain.DnsBlocked || changes != 1) throw new Exception("Checkbox choice was not committed immediately");
        checkbox.IsChecked = false;
        if (domain.DnsBlocked || changes != 2) throw new Exception("Checkbox clear was not committed");
        Console.WriteLine("PASS WPF checkbox commits select and clear through real two-way binding");
        var committed = new List<DeviceDomainRuleState>();
        var row = new DeviceDomainRuleVm("fixture.invalid", DeviceDomainRuleState.Inherit, state => { committed.Add(state); return true; }, state => state.ToString());
        var combo = new ComboBox { ItemsSource = Enum.GetValues<DeviceDomainRuleState>() };
        BindingOperations.SetBinding(combo, System.Windows.Controls.Primitives.Selector.SelectedItemProperty,
            new Binding(nameof(DeviceDomainRuleVm.State)) { Source = row, Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        foreach (var state in new[] { DeviceDomainRuleState.Allow, DeviceDomainRuleState.Block, DeviceDomainRuleState.Inherit }) combo.SelectedItem = state;
        if (!committed.SequenceEqual(new[] { DeviceDomainRuleState.Allow, DeviceDomainRuleState.Block, DeviceDomainRuleState.Inherit })
            || row.Indicator != "○ INHERIT" || row.Effective != "Inherit") throw new Exception("Override edit commit failed");
        Console.WriteLine("PASS WPF override selection commits Allow, Block, Inherit and updates textual indicators");
        var refused = new DeviceDomainRuleVm("fixture.invalid", DeviceDomainRuleState.Inherit, _ => false, state => state.ToString());
        refused.State = DeviceDomainRuleState.Block;
        if (refused.State != DeviceDomainRuleState.Inherit || refused.Indicator != "○ INHERIT") throw new Exception("Failed edit changed presented state");
        Console.WriteLine("PASS WPF rejected override commit retains previous selection and indicator");
        UxTests.Run(args.FirstOrDefault());
        return 0;
    }
}
