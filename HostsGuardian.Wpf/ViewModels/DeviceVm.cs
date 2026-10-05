using L = HostsGuardian.Wpf.Localization.LocalizationService;
using System;
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

    public Guid? DeviceId { get; set; }
    public DateTimeOffset? ObservedAtUtc { get; set; }
    public string ObservationState => ObservedAtUtc is { } observed && DateTimeOffset.UtcNow - observed <= TimeSpan.FromMinutes(5)
        ? L.T("Recently observed (scan)") : L.T("Unknown / observation stale");
    public string IdentitySummary => L.F("IP: {0}; MAC: {1}; DeviceId: {2}; {3}", Ip, (Mac == "" ? L.T("unknown") : Mac), DeviceId?.ToString() ?? L.T("unassigned"), ObservationState);
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

    // Emoji icon that ALWAYS renders (with Segoe UI Emoji in XAML)
    public string Icon => Kind switch
    {
        DeviceKind.Router => "📡",
        DeviceKind.Pc => "🖥️",
        DeviceKind.Laptop => "💻",
        DeviceKind.Phone => "📱",
        DeviceKind.Tablet => "📲",
        DeviceKind.Tv => "📺",
        DeviceKind.Console => "🎮",
        DeviceKind.Printer => "🖨️",
        DeviceKind.IoT => "🔌",
        _ => "❓"
    };

    public string DisplayName
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Name)) return Name.Trim();
            if (!string.IsNullOrWhiteSpace(Hostname)) return Hostname.Trim();
            if (!string.IsNullOrWhiteSpace(VendorHint)) return VendorHint.Trim();
            return Ip;
        }
    }

    public DeviceVm(NetworkDevice dev, string? policyName, bool isBlocked)
    {
        _dev = dev ?? throw new ArgumentNullException(nameof(dev));

        _name = policyName ?? "";
        LegacyPreference = isBlocked ? L.T("Legacy block preference: unassigned; review required") : "";

        RecalcKindAndPresentation();
    }

    public void Relocalize() { OnPropertyChanged(nameof(ObservationState)); OnPropertyChanged(nameof(IdentitySummary)); OnPropertyChanged(nameof(LegacyPreference)); }

    // ---- Heuristics ----
    private void RecalcKindAndPresentation()
    {
        Kind = GuessKind();

        // ha a Kind nem változik, attól még lehet a DisplayName változott
        OnPropertyChanged(nameof(Icon));
        OnPropertyChanged(nameof(DisplayName));
    }

    private DeviceKind GuessKind()
    {
        var s = $"{Name} {Hostname} {VendorHint}".ToLowerInvariant();

        // Router/gateway hints
        if (s.Contains("router") || s.Contains("gateway") || s.Contains("t-home") || s.Contains("telekom") || s.Contains("speedport"))
            return DeviceKind.Router;

        // Consoles
        if (s.Contains("xbox") || s.Contains("playstation") || s.Contains("ps5") || s.Contains("ps4") || s.Contains("nintendo") || s.Contains("switch"))
            return DeviceKind.Console;

        // TV / media
        if (s.Contains("chromecast") || s.Contains("firetv") || s.Contains("bravia") || s.Contains("android tv") || s.Contains("smart tv"))
            return DeviceKind.Tv;

        // LG webOS (zárójel: különben félremehet)
        if (s.Contains("lg") && s.Contains("webos"))
            return DeviceKind.Tv;

        if (s.Contains("tv"))
            return DeviceKind.Tv;

        // Printers
        if (s.Contains("printer") || (s.Contains("hp") && s.Contains("print")) || s.Contains("epson") || s.Contains("canon") || s.Contains("brother"))
            return DeviceKind.Printer;

        // Phones/tablets
        if (s.Contains("iphone") || s.Contains("android") || s.Contains("samsung") || s.Contains("xiaomi") || s.Contains("huawei") || s.Contains("pixel") || s.Contains("s22"))
            return DeviceKind.Phone;

        if (s.Contains("ipad") || s.Contains("tablet"))
            return DeviceKind.Tablet;

        // Laptops/PC
        if (s.Contains("legion") || s.Contains("thinkpad") || s.Contains("laptop") || s.Contains("notebook") || s.Contains("vivobook"))
            return DeviceKind.Laptop;

        if (s.Contains("pc") || s.Contains("desktop") || s.Contains("windows"))
            return DeviceKind.Pc;

        // IoT
        if (s.Contains("iot") || s.Contains("camera") || s.Contains("bulb") || s.Contains("plug") || s.Contains("tuya") || s.Contains("sonoff"))
            return DeviceKind.IoT;

        return DeviceKind.Unknown;
    }
}