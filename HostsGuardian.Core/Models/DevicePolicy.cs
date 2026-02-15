using System;

namespace HostsGuardian.Core.Models
{
    public sealed class DevicePolicy
    {
        // Azonosítás (egyik elég)
        public string Ip { get; set; } = "";       // pl "192.168.1.114"
        public string Mac { get; set; } = "";      // pl "AA:BB:CC:DD:EE:FF"

        // Felhasználóbarát név
        public string Name { get; set; } = "";     // "Timi iPhone", "TV", "Laptop" stb.

        // Policy
        public bool IsBlocked { get; set; }

        public string Notes { get; set; } = "";
        public DateTime? UpdatedAtUtc { get; set; }
    }
}
