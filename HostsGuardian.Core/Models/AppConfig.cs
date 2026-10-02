using System;
using System.Collections.Generic;
using HostsGuardian.Core.Models;



namespace HostsGuardian.Core.Models
{
    public sealed class AppConfig
    {
        public List<DomainEntry> BlockedDomains { get; set; } = new();

        // per-device blokkolási policy (router/DNS irányhoz)
        public List<DevicePolicy> DevicePolicies { get; set; } = new();

        public DnsEngineConfig DnsEngine { get; set; } = new();


        public string? LastAppliedBy { get; set; }
        public DateTime? LastAppliedAtUtc { get; set; }
    }
}
