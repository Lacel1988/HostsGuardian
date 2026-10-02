using System.Collections.Generic;
using System.Linq;
using System.Text;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services
{
    public sealed class DnsBlockService
    {
        // Pi-hole / router style
        public string BuildZeroIpList(IEnumerable<DomainEntry> domains)
        {
            var clean = Normalize(domains);

            var sb = new StringBuilder();

            foreach (var d in clean)
            {
                sb.AppendLine($"0.0.0.0 {d}");
            }

            return sb.ToString();
        }

        // AdGuard / uBlock style
        public string BuildAdGuardList(IEnumerable<DomainEntry> domains)
        {
            var clean = Normalize(domains);

            var sb = new StringBuilder();

            foreach (var d in clean)
            {
                sb.AppendLine($"||{d}^");
            }

            return sb.ToString();
        }

        private static List<string> Normalize(IEnumerable<DomainEntry> domains)
        {
            return domains
                .Where(d => d.DnsBlocked)
                .Select(d => HostsService.NormalizeDomain(d.Domain))
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Distinct()
                .OrderBy(d => d)
                .ToList();
        }
    }
}
