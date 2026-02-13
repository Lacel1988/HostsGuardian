using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;

namespace HostsGuardian.Core.Services
{
    public sealed class DnsStatus
    {
        public List<string> DnsServers { get; set; } = new();
        public List<string> Notes { get; set; } = new();
    }

    public sealed class DnsInfoService
    {
        public DnsStatus GetStatus()
        {
            var servers = new HashSet<string>();

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                var props = ni.GetIPProperties();
                foreach (var dns in props.DnsAddresses)
                    servers.Add(dns.ToString());
            }

            var status = new DnsStatus
            {
                DnsServers = servers.OrderBy(x => x).ToList()
            };

            if (status.DnsServers.Count == 0)
                status.Notes.Add("No DNS servers detected (network down or restricted).");

            if (status.DnsServers.Any(s => s.StartsWith("127.")))
                status.Notes.Add("DNS points to localhost (possible local resolver / filtering).");

            // DoH-t itt direkt nem “hazudjuk be” detektálás nélkül
            status.Notes.Add("DoH detection: not implemented (info-only).");

            return status;
        }
    }
}
