using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public static class DomainPolicySelection
{
    public static string[] ForHosts(IEnumerable<DomainEntry>? entries)
        => Select(entries, entry => entry.HostsBlocked);

    public static string[] ForDns(IEnumerable<DomainEntry>? entries)
        => Select(entries, entry => entry.DnsBlocked);

    private static string[] Select(IEnumerable<DomainEntry>? entries, Func<DomainEntry, bool> selected)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries ?? Enumerable.Empty<DomainEntry>())
        {
            if (entry == null || !selected(entry)) continue;
            var domain = DomainName.Normalize(entry.Domain);
            if (domain.Length == 0) throw new ArgumentException("A selected domain is invalid. Correct it before applying policy.");
            result.Add(domain);
        }
        return result.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
