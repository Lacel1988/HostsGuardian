using HostsGuardian.Core.Models;
using HostsGuardian.Wpf.Infrastructure;

namespace HostsGuardian.Wpf.ViewModels
{
    public sealed class DeviceVm : ObservableObject
    {
        private readonly NetworkDevice _device;

        public string Ip => _device.Ip;
        public string Mac
        {
            get => _device.Mac;
            set
            {
                if (_device.Mac != value)
                {
                    _device.Mac = value ?? "";
                    OnPropertyChanged(nameof(Mac));
                }
            }
        }

        public string Hostname
        {
            get => _device.Hostname;
            set
            {
                if (_device.Hostname != value)
                {
                    _device.Hostname = value ?? "";
                    OnPropertyChanged(nameof(Hostname));
                    OnPropertyChanged(nameof(DisplayName));
                }
            }
        }

        public string VendorHint
        {
            get => _device.VendorHint;
            set
            {
                if (_device.VendorHint != value)
                {
                    _device.VendorHint = value ?? "";
                    OnPropertyChanged(nameof(VendorHint));
                    OnPropertyChanged(nameof(DisplayName));
                }
            }
        }

        // Felhasználó által adott "név" (policy)
        private string _name = "";
        public string Name
        {
            get => _name;
            set
            {
                if (Set(ref _name, value ?? ""))
                    OnPropertyChanged(nameof(DisplayName));
            }
        }

        private bool _dnsBlocked;
        public bool DnsBlocked
        {
            get => _dnsBlocked;
            set => Set(ref _dnsBlocked, value);
        }

        // UI-ban hasznos: ha a Name üres, akkor Hostname, ha az is üres, akkor IP
        public string DisplayName
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Name)) return Name;
                if (!string.IsNullOrWhiteSpace(Hostname)) return Hostname;
                return Ip;
            }
        }

        // EZ A KONSTRUKTOR KELL a MainViewModel-hez lentebb:
        public DeviceVm(NetworkDevice device, string? policyName, string? policyMac, bool dnsBlocked)
        {
            _device = device;

            Name = policyName ?? "";
            if (!string.IsNullOrWhiteSpace(policyMac) && string.IsNullOrWhiteSpace(_device.Mac))
                _device.Mac = policyMac!;

            DnsBlocked = dnsBlocked;
        }

        // Ezt akkor hívjuk, amikor mentjük vissza config.json-be
        public NetworkDevice AsDevice() => _device;
    }
}
