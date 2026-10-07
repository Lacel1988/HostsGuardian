using L = HostsGuardian.Wpf.Localization.LocalizationService;
using System;
using HostsGuardian.Core.Services;
using HostsGuardian.Core.Models;
using HostsGuardian.Wpf.Infrastructure;

namespace HostsGuardian.Wpf.ViewModels;

public sealed class DeviceVm : ObservableObject
{
    private readonly NetworkDevice _dev;

    // ==== Core identity ====
    public string Ip => _dev.Ip;

    public string Mac
    {
        get => _dev.Mac;
        set
        {
            var v = value ?? "";
            if (!string.Equals(_dev.Mac, v, StringComparison.OrdinalIgnoreCase))
            {
                _dev.Mac = v;
                OnPropertyChanged();
                RecalcKindAndPresentation();
            }
        }
    }

    public string Hostname
    {
        get => _dev.Hostname;
        set
        {
            var v = value ?? "";
            if (!string.Equals(_dev.Hostname, v, StringComparison.OrdinalIgnoreCase))
            {
                _dev.Hostname = v;
                OnPropertyChanged();
                RecalcKindAndPresentation();
            }
        }
    }

    public string VendorHint
    {
        get => _dev.VendorHint;
        set
        {
            var v = value ?? "";
            if (!string.Equals(_dev.VendorHint, v, StringComparison.OrdinalIgnoreCase))
            {
                _dev.VendorHint = v;
                OnPropertyChanged();
                RecalcKindAndPresentation();
            }
        }
    }

    // ==== Policy fields (persisted in config.json) ====
    private string _name = "";
    public string Name
    {
        get => _name;
        set
        {
            var v = value ?? "";
            if (Set(ref _name, v))
            {
                RecalcKindAndPresentation();
            }
        }
    }

    private Guid? _deviceId;
    private bool _registrationVerified;
    public bool IsRegistered=>DeviceId!=null && _registrationVerified;
    public Guid? DeviceId { get => _deviceId; set { if(Set(ref _deviceId,value)) { _registrationVerified=false;OnPropertyChanged(nameof(IsRegistered));OnPropertyChanged(nameof(IdentityStateText)); OnPropertyChanged(nameof(IdentitySummary)); OnPropertyChanged(nameof(InventoryStateText)); } } }
    private LanDeviceObservation? _lanObservation;
    private readonly ClassificationReadModel _classificationReadModel=new();
    public LanDeviceObservation? LanObservation { get=>_lanObservation;set {var resolved=value is null?null:_classificationReadModel.Apply(value,DateTimeOffset.UtcNow);if(Set(ref _lanObservation,resolved)){RecalcKindAndPresentation();Relocalize();}} }
    public void RefreshTypePresentation(){RecalcKindAndPresentation();OnPropertyChanged(nameof(PresenceText));OnPropertyChanged(nameof(ObservationState));}
    public DateTimeOffset? LastSeenUtc {get;init;}
    public string[] RegisteredGroups {get;set;}=[];
    public InferredClassificationMemory? RetainedClassification {get;init;}
    public string InventoryStateText=>L.T(IsRegistered?"Inventory.Known":"Inventory.Discovered");
    public string IdentityStateText => IsRegistered ? L.T("Registered identity in local draft; delivery is explicit.") : L.T("Provisional identity; no unique user registration.");
    public string PresenceText => LanObservation is {} lan ? L.T(lan.LastObservedUtc<DateTimeOffset.UtcNow.AddMinutes(-5) || lan.Evidence.Any(e=>e.NeighborState=="STALE") ? "Observed cached presence; online state unproven." : "Network presence observed; online state unproven.") + "\n" + lan.LastObservedUtc.ToLocalTime().ToString("HH:mm:ss") : L.T("Independent presence unknown.")+(LastSeenUtc is {} last?"\n"+L.F("Inventory.LastSeen",last.ToLocalTime().ToString("yyyy-MM-dd HH:mm")):"");
    public string NetworkText => LanObservation is {} lan ? string.Join("\n",lan.Evidence.Select(e=>e.Address).Distinct()) + "\nMAC: " + string.Join(", ",lan.Evidence.Select(e=>e.Mac).Where(m=>m!="").Distinct()) : Ip + "\nMAC: " + Mac;
    public string DnsActivityText => L.T(LanObservation?.DnsActivity ?? "NOT OBSERVED");
    public string CoverageText => L.T(LanObservation?.Coverage ?? "UNKNOWN") + "\n" + L.T("Resolver path") + ": " + L.T(LanObservation?.ResolverPath ?? "UNKNOWN");
    public string CoverageWhy => L.T(LanObservation?.DnsActivity=="OBSERVED" ? "DNS use observed; exclusive coverage is not proven." : "No correlated DNS activity. Idle state or another resolver remain possible.");
    public string LanSummary => LanObservation is {} lan ?
        L.T("LAN presence")+": "+L.T("Observed")+"; "+L.T("DNS activity")+": "+L.T(lan.DnsActivity)+"; "+
        L.T("DNS coverage")+": "+L.T(lan.Coverage)+"; "+L.T("Resolver path")+": "+L.T(lan.ResolverPath)+"\n"+
        L.T("Network bindings")+": "+string.Join(", ",lan.Evidence.Select(e=>e.Address).Distinct())+"\n"+
        L.T("Session observation identity; not a permanent device registration.") : L.T("Independent LAN evidence unavailable; DNS coverage unknown.");
    public DateTimeOffset? ObservedAtUtc { get; set; }
    public string ObservationState => ObservedAtUtc is { } observed && DateTimeOffset.UtcNow - observed <= TimeSpan.FromMinutes(5)
        ? L.T("Recently observed (scan)") : L.T("Unknown / observation stale");
    public string IdentitySummary => _dev.IdentityEvidence + "; " + L.T("Vendor hint") + ": " + (VendorHint=="" ? L.T("unknown") : VendorHint + " (INFERRED)") + "; " + L.F("IP: {0}; MAC: {1}; DeviceId: {2}; {3}", Ip, (Mac == "" ? L.T("unknown") : Mac), DeviceId?.ToString() ?? L.T("unassigned"), ObservationState)
        + "\n" + L.T("Observed hostname") + ": " + (Hostname==""?L.T("unknown"):Hostname)
        + (LanObservation?.Identity is {} identity ? "\n" + L.T("Identity provenance") + ": " + identity.Provenance + "\n" + L.T("Groups") + ": " + string.Join(", ",identity.Groups) : RegisteredGroups.Length>0 ? "\n"+L.T("Groups")+": "+string.Join(", ",RegisteredGroups) : "");
    private string _legacyPreference = "";
    public string LegacyPreference { get => L.T(_legacyPreference); set => _legacyPreference = value; }

    // ==== Presentation ====
    private DeviceKind _kind = DeviceKind.Unknown;
    public DeviceKind Kind
    {
        get => _kind;
        private set
        {
            if (Set(ref _kind, value))
            {
                OnPropertyChanged(nameof(Icon));
                OnPropertyChanged(nameof(DisplayName));
            }
        }
    }

    private string _confirmedType="";
    private string? _typeChoice;
    public string ConfirmedType {get=>_confirmedType;set {if(Set(ref _confirmedType,value??""))RecalcKindAndPresentation();}}
    public IReadOnlyList<DeviceTypeChoiceVm> TypeChoices {get;} = new[]{new DeviceTypeChoiceVm("")}.Concat(DeviceTypes.All.Select(t=>new DeviceTypeChoiceVm(t.Id))).ToArray();
    public string SelectedTypeId {get=>_typeChoice ?? DeviceTypes.Find(ConfirmedType)?.Id ?? "";set {if(value==SelectedTypeId)return;_typeChoice=value;RecalcKindAndPresentation();OnPropertyChanged(nameof(SelectedTypeId));}}
    public bool TypeEdited => _typeChoice!=null;
    public string TypeToSave => _typeChoice ?? ConfirmedType;
    public void AcceptTypeDraft() {_confirmedType=TypeToSave;_typeChoice=null;RecalcKindAndPresentation();}
    public bool ClearOrphanedRegistration(FullDnsPolicy registry)
    {
        if(DeviceId is not Guid id || registry.Devices.Any(d=>d.DeviceId==id))return false;
        DeviceId=null;Name="";_confirmedType="";_typeChoice=null;RegisteredGroups=[];
        if(LanObservation is {} observation)
            LanObservation=DeviceIdentityProjection.Apply([observation],FullDnsPolicy.Empty).Single();
        RecalcKindAndPresentation();Relocalize();return true;
    }
    public void ApplyRegistration(DeviceRegistration registration,FullDnsPolicy policy)
    {
        DeviceId=registration.DeviceId;Name=DeviceIdentityProjection.FriendlyName(registration);
        _confirmedType=registration.Metadata?.Type ?? "";_typeChoice=null;
        RegisteredGroups=policy.Program?.Groups.Where(g=>g.DeviceIds.Contains(registration.DeviceId)).Select(g=>g.Name).ToArray() ?? [];
        _registrationVerified=true;OnPropertyChanged(nameof(IsRegistered));OnPropertyChanged(nameof(InventoryStateText));OnPropertyChanged(nameof(IdentityStateText));
        RecalcKindAndPresentation();Relocalize();
    }
    public DeviceTypeAssessment TypeAssessment => DeviceTypes.Present(TypeToSave,LanObservation?.Classification,LanObservation?.Evidence.Select(e=>e.Hostname) ?? new[]{Hostname},DateTimeOffset.UtcNow,LanObservation?.LastReliableClassification ?? RetainedClassification);
    public string Icon => TypeAssessment.Type.IconKey;
    public string IconPath => TypeAssessment.Type.IconPath;
    public string TypeLabel => L.T("Type."+TypeAssessment.Type.Id);
    public string TypeFreshnessText => TypeAssessment.Source=="INFERRED" && TypeAssessment.LastClassifiedUtc is {} time ? " · "+L.T("Fingerprint."+TypeAssessment.EvidenceState)+" · "+L.F("Fingerprint.LastClassified",time.ToLocalTime().ToString("yyyy-MM-dd HH:mm")) : "";
    public string TypeStateText => TypeLabel+" · "+(TypeAssessment.Source=="INFERRED" ? L.F("Type.InferredConfidence",L.T("Confidence."+TypeAssessment.Confidence)) : L.T(TypeEdited?"Type.Draft":TypeAssessment.Source=="USER-CONFIRMED"?"Type.Confirmed":"Type.NoEvidence"))+TypeFreshnessText;
    public string TypeProvenance => TypeAssessment.Source+" / "+TypeAssessment.Confidence+" · "+TypeAssessment.Provenance+string.Concat((LanObservation?.Classification?.Evidence ?? []).Select(e=>"\n"+e.Provider+" · "+e.Kind+": "+e.Value));

    public string DisplayName
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Name)) return Name.Trim();
            if (!string.IsNullOrWhiteSpace(Hostname)) return Hostname.Trim() + (_dev.Notes=="LocalOsEvidence" ? " · " + L.T("This computer") : _dev.Notes=="EngineEndpointEvidence" ? " · " + L.T("Engine host") : "");
            if (!string.IsNullOrWhiteSpace(VendorHint)) return L.T("Unknown device") + " · " + VendorHint.Trim();
            return TypeAssessment.Source=="INFERRED" ? L.F("Likely {0}",TypeLabel) : L.T("Unknown device");
        }
    }

    public DeviceVm(NetworkDevice dev, string? policyName, bool isBlocked)
    {
        _dev = dev ?? throw new ArgumentNullException(nameof(dev));

        _name = policyName ?? "";
        LegacyPreference = isBlocked ? L.T("Legacy block preference: unassigned; review required") : "";

        RecalcKindAndPresentation();
    }

    public void Relocalize() { foreach(var property in new[]{nameof(DisplayName),nameof(ObservationState),nameof(IdentitySummary),nameof(LegacyPreference),nameof(LanSummary),nameof(IdentityStateText),nameof(PresenceText),nameof(NetworkText),nameof(DnsActivityText),nameof(CoverageText),nameof(CoverageWhy),nameof(TypeLabel),nameof(TypeStateText),nameof(TypeProvenance),nameof(InventoryStateText)}) OnPropertyChanged(property); foreach(var choice in TypeChoices)choice.Relocalize(); }

    // ---- Heuristics ----
    private void RecalcKindAndPresentation()
    {
        Kind = GuessKind();

        // ha a Kind nem változik, attól még lehet a DisplayName változott
        OnPropertyChanged(nameof(Icon));
        OnPropertyChanged(nameof(DisplayName));
        foreach(var property in new[]{nameof(IconPath),nameof(SelectedTypeId),nameof(TypeLabel),nameof(TypeStateText),nameof(TypeProvenance),nameof(TypeEdited)})OnPropertyChanged(property);
    }

    private DeviceKind GuessKind() => TypeAssessment.Type.Id switch
    {
        "Phone"=>DeviceKind.Phone,"Tablet"=>DeviceKind.Tablet,"Laptop"=>DeviceKind.Laptop,"Computer"=>DeviceKind.Pc,
        "TV"=>DeviceKind.Tv,"Console"=>DeviceKind.Console,"Printer"=>DeviceKind.Printer,"Network"=>DeviceKind.Router,
        "IoT"=>DeviceKind.IoT,_=>DeviceKind.Unknown
    };
}

public sealed class DeviceTypeChoiceVm(string id) : ObservableObject
{
    public static System.Windows.DataTemplate LabelTemplate()
    {
        var text=new System.Windows.FrameworkElementFactory(typeof(System.Windows.Controls.TextBlock));
        text.SetBinding(System.Windows.Controls.TextBlock.TextProperty,new System.Windows.Data.Binding(nameof(Label)));
        return new System.Windows.DataTemplate {VisualTree=text};
    }
    public string Id=>id;
    public string Label=>L.T(id==""?"Type.Auto":"Type."+id);
    public void Relocalize()=>OnPropertyChanged(nameof(Label));
}
