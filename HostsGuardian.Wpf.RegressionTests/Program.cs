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
        FingerprintLifecycleTests.Run();
        var registeredId=Guid.NewGuid();var inventoryPolicy=FullDnsPolicy.Empty with{SchemaVersion=3,Devices=[new(registeredId,"Old name","02:DE:AD:BE:EF:01","fixture","User"){Metadata=new("Named console","Owner","Console","Room")}],Program=PolicyProgram.Empty};
        var oldRow=new DeviceVm(new NetworkDevice{Ip="192.0.2.1"},"Named console",false){DeviceId=registeredId,ObservedAtUtc=DateTimeOffset.UtcNow.AddMinutes(-11)};
        var offline=DeviceInventoryView.Merge([],inventoryPolicy,[oldRow]).Single();
        if(offline.DeviceId!=registeredId || offline.DisplayName!="Named console" || offline.TypeAssessment.Source!="USER-CONFIRMED" || offline.TypeAssessment.Type.Id!="Console" || offline.LastSeenUtc!=oldRow.ObservedAtUtc || offline.PresenceText.Contains("online state unproven")==false && !offline.PresenceText.Contains("unknown"))throw new Exception("Offline inventory lost metadata or fabricated online state");
        if(DeviceInventoryView.Merge([],HostsGuardian.Core.Services.DeviceInventory.Forget(inventoryPolicy,registeredId)).Length!=0)throw new Exception("Forgotten registry restored metadata");
        Console.WriteLine("PASS registered offline inventory retains friendly metadata/type and last seen; explicit forget removes entry");
        var classifiedAt=DateTimeOffset.UtcNow.AddMinutes(-6);
        var summary=new InferredClassificationMemory(new("TV","Medium","INFERRED","Category agrees with renderer",classifiedAt,[]),["SSDP · DeviceRole"],DateTimeOffset.UtcNow.AddHours(23));
        var staleVm=new DeviceVm(new NetworkDevice{Ip="192.0.2.8"},null,false){RetainedClassification=summary};
        if(staleVm.TypeAssessment.Type.Id!="TV" || staleVm.TypeAssessment.EvidenceState!="STALE" || staleVm.Icon!="device-tv" || staleVm.TypeAssessment.LastClassifiedUtc!=classifiedAt)throw new Exception("Stale inference lost type/icon/timestamp");
        staleVm.ConfirmedType="Console";if(staleVm.TypeAssessment.Type.Id!="Console" || staleVm.TypeAssessment.Source!="USER-CONFIRMED")throw new Exception("Stale inference overwrote user type");
        Console.WriteLine("PASS stale reliable inference retains TV icon/confidence/timestamp while explicit user type stays authoritative");
        var unknownVm=new DeviceVm(new NetworkDevice {Ip="192.0.2.1",VendorHint="Samsung"},null,false);
        if(unknownVm.Kind!=DeviceKind.Unknown || unknownVm.DeviceId!=null || !unknownVm.DisplayName.Contains("Samsung")) throw new Exception("Vendor-only evidence fabricated a phone/identity");
        unknownVm.SelectedTypeId="Phone";
        if(unknownVm.DeviceId!=null || !unknownVm.TypeEdited || unknownVm.TypeAssessment.Type.Id!="Phone")throw new Exception("Type choice created identity or was lost");
        unknownVm.AcceptTypeDraft();
        if(unknownVm.ConfirmedType!="Phone" || unknownVm.TypeEdited || unknownVm.Icon!="device-phone" || string.IsNullOrWhiteSpace(unknownVm.IconPath))throw new Exception("Confirmed type/icon persistence failed");
        Console.WriteLine("PASS explicit provisional type choice remains separate from identity and uses shared vector icon");
        var inferredVm=new DeviceVm(new NetworkDevice {Ip="192.0.2.9"},null,false);
        inferredVm.LanObservation=new(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",DateTimeOffset.UtcNow,DateTimeOffset.UtcNow,[]){Classification=new("Printer","High","INFERRED","Independent fixture role agreement",DateTimeOffset.UtcNow,[])};
        if(inferredVm.TypeAssessment.Type.Id!="Printer" || inferredVm.TypeAssessment.Confidence!="High")throw new Exception("WPF omitted classification");
        var typeUpdates=0;inferredVm.PropertyChanged+=(_,e)=>{if(e.PropertyName==nameof(DeviceVm.IconPath))typeUpdates++;};
        inferredVm.RefreshTypePresentation();if(typeUpdates!=1)throw new Exception("Type freshness timer does not notify vector bindings");
        inferredVm.ConfirmedType="Unknown";if(inferredVm.TypeAssessment.Source!="USER-CONFIRMED" || inferredVm.TypeAssessment.Type.Id!="Unknown")throw new Exception("Inference overwrote explicit Unknown");
        Console.WriteLine("PASS WPF consumes shared inferred confidence without overwriting user-confirmed type");
        var observedVm=new DeviceVm(new NetworkDevice {Ip="192.0.2.2",Hostname="Observed-host",Mac="02:00:00:00:00:01"},null,false);
        if(observedVm.DisplayName!="Observed-host" || observedVm.DeviceId!=null) throw new Exception("Observed hostname became a stable identity");
        observedVm.Name="Confirmed alias";if(observedVm.DisplayName!="Confirmed alias") throw new Exception("Alias did not override discovery metadata");
        Console.WriteLine("PASS passive identity names, neutral vendor-only type and alias precedence preserve unassigned identity");
        observedVm.LanObservation=new(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",DateTimeOffset.UtcNow,DateTimeOffset.UtcNow,
            [new("192.0.2.2","02:00:00:00:00:01","","OBSERVED: fixture",DateTimeOffset.UtcNow)]);
        HostsGuardian.Wpf.Localization.LocalizationService.Instance.ChangeLanguage("en",persist:false);
        if(!observedVm.LanSummary.Contains("DNS activity: NOT OBSERVED") || !observedVm.LanSummary.Contains("DNS coverage: UNKNOWN"))throw new Exception("LAN presence falsely implies DNS use");
        HostsGuardian.Wpf.Localization.LocalizationService.Instance.ChangeLanguage("hu",persist:false);
        if(!observedVm.LanSummary.Contains("NEM MEGFIGYELT") || !observedVm.LanSummary.Contains("LAN-jelenlét"))throw new Exception("Hungarian discovery evidence not localized");
        HostsGuardian.Wpf.Localization.LocalizationService.Instance.ChangeLanguage("en",persist:false);
        Console.WriteLine("PASS independent LAN presence, DNS absence and unknown coverage localize without identity registration");
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
        var ruleId = Guid.NewGuid();
        DecisionEvidence[] evidence = [
            new(PolicyLayer.ActiveProfile, DeviceDomainRuleState.Block, "ActiveSchedule", "fixture.invalid", ruleId),
            new(PolicyLayer.DeviceGroup, DeviceDomainRuleState.Allow, "GroupRule", "fixture.invalid")];
        var localization = HostsGuardian.Wpf.Localization.LocalizationService.Instance;
        var originalLanguage = localization.Language;
        try
        {
            localization.ChangeLanguage("en", false);
            if(localization["DNS coverage"]!="DNS coverage") throw new Exception("English coverage label missing");
            var english = HostsGuardian.Wpf.Services.DecisionEvidencePresentation.Format(evidence);
            localization.ChangeLanguage("hu", false);
            if(localization["DNS coverage"]!="DNS-lefedettség" || localization["PARTIAL"]!="RÉSZLEGES") throw new Exception("Hungarian coverage presentation missing");
            var hungarian = HostsGuardian.Wpf.Services.DecisionEvidencePresentation.Format(evidence);
            localization.ChangeLanguage("en", false);
            if (!english.Contains("Winning rule") || !english.Contains("Overridden rule") ||
                !hungarian.Contains("Aktív profil/ütemezés") || !hungarian.Contains("Eszközcsoport") ||
                !hungarian.Contains(ruleId.ToString()) ||
                english != HostsGuardian.Wpf.Services.DecisionEvidencePresentation.Format(evidence))
                throw new Exception("Decision evidence lost winning/overridden provenance or live language consistency");
        }
        finally { localization.ChangeLanguage(originalLanguage, false); }
        Console.WriteLine("PASS EN/HU winning and overridden policy evidence retains provenance and language roundtrip");
        UxTests.Run(args.FirstOrDefault());
        RoadmapUxTests.Run();
        RegistrationConsistencyTests.Run();
        NotificationAcceptanceTests.Run();
        return 0;
    }
}
