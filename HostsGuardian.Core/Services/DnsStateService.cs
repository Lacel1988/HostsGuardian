using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace HostsGuardian.Wpf.Services
{
    public sealed class DnsState
    {
        public List<string> Servers { get; set; } = new();
        public string RiskLabel { get; set; } = "UNKNOWN";   // OK | RISKY | UNKNOWN
        public string Summary { get; set; } = "";
        public string Details { get; set; } = "";
        public DateTime AtUtc { get; set; } = DateTime.UtcNow;
    }

    public sealed class DnsStateService
    {
        private static readonly HashSet<string> KnownPublicDns = new(StringComparer.OrdinalIgnoreCase)
        {
            // Cloudflare
            "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
            // Google
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
            // Quad9
            "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
            // OpenDNS
            "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",
            // AdGuard
            "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"
        };

        public DnsState GetState()
        {
            var state = new DnsState();
            state.AtUtc = DateTime.UtcNow;

            var servers = new List<IPAddress>();

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                try
                {
                    var ipProps = ni.GetIPProperties();
                    if (ipProps?.DnsAddresses == null || ipProps.DnsAddresses.Count == 0)
                        continue;

                    servers.AddRange(ipProps.DnsAddresses);
                }
                catch
                {
                    // info-only: ha egy interface nem olvasható, kihagyjuk
                }
            }

            // unique + string form
            var clean = servers
                .Select(ip => ip.ToString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            state.Servers = clean;

            if (clean.Count == 0)
            {
                state.RiskLabel = "UNKNOWN";
                state.Summary = "No DNS servers found from active network interfaces.";
                state.Details =
                    "This can happen if Windows reports DNS via a different path, " +
                    "or interfaces are restricted.\n\n" +
                    "Note: Browser DoH can bypass OS DNS settings. External detection is not reliable.";
                return state;
            }

            var hasPublic = clean.Any(s => KnownPublicDns.Contains(s));

            state.RiskLabel = hasPublic ? "RISKY" : "OK";

            state.Summary = hasPublic
                ? "Public DNS detected. Hosts blocking can be bypassed easier."
                : "DNS looks normal. Hosts blocking is more reliable (still not perfect).";

            state.Details =
                "Detected DNS servers:\n" +
                string.Join("\n", clean.Select(s => "  - " + s)) +
                "\n\n" +
                "Important:\n" +
                "Browser DoH (DNS over HTTPS) may bypass OS DNS + hosts behavior.\n" +
                "We cannot reliably detect browser DoH from here. This panel is info-only.";

            return state;
        }
    }
}
