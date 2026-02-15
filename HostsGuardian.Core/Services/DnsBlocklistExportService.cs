using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services
{
    public sealed class DnsBlocklistExportService
    {
        // AdGuard / Pi-hole kompatibilis: soronként domain
        public string ExportDomainsPlain(IEnumerable<DomainEntry> domains)
        {
            var clean = (domains ?? Enumerable.Empty<DomainEntry>())
                .Select(d => (d?.Domain ?? "").Trim())
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Select(HostsService.NormalizeDomain)
                .Where(d => !string.IsNullOrWhiteSpace(d) && d.Contains('.'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var sb = new StringBuilder();
            sb.AppendLine("# HostsGuardian DNS blocklist export");
            sb.AppendLine("# Format: one domain per line (AdGuard Home / Pi-hole compatible)");
            sb.AppendLine("# Generated at (UTC): " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine();

            foreach (var dom in clean)
                sb.AppendLine(dom);

            return sb.ToString();
        }

        // Opcionális "hosts-style" export (ha valaki mégis hosts importtal dolgozna)
        public string ExportHostsStyle(IEnumerable<DomainEntry> domains)
        {
            var clean = (domains ?? Enumerable.Empty<DomainEntry>())
                .Select(d => (d?.Domain ?? "").Trim())
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Select(HostsService.NormalizeDomain)
                .Where(d => !string.IsNullOrWhiteSpace(d) && d.Contains('.'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var sb = new StringBuilder();
            sb.AppendLine("# HostsGuardian hosts-style export");
            sb.AppendLine("# Format: 0.0.0.0 domain (not recommended for modern DNS filter engines)");
            sb.AppendLine("# Generated at (UTC): " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine();

            foreach (var dom in clean)
            {
                sb.AppendLine("0.0.0.0 " + dom);
                sb.AppendLine("0.0.0.0 www." + dom);
            }

            return sb.ToString();
        }
    }
}
