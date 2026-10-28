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

        // DevicePolicies remain unassigned legacy review information; never convert IsBlocked.
        public FullDnsPolicy DeviceDomainPolicy { get; set; } = FullDnsPolicy.Empty;
        // Local-only pre-edit values. Retained across delivery/restart; never sent to Engine.
        public List<HostsGuardian.Core.Services.DeviceOverrideRestorePoint> DeviceRuleRestorePoints { get; set; } = new();

        public DnsEngineConfig DnsEngine { get; set; } = new();


        public string? LastAppliedBy { get; set; }
        public DateTime? LastAppliedAtUtc { get; set; }
    }
}
