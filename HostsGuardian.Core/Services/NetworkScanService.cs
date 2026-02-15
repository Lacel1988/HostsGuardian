using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public sealed class NetworkScanService
{
    public IReadOnlyList<NetworkDevice> ScanLanBestEffort(int maxHostsToProbe = 64, int timeoutMs = 120)
    {
        var gateway = GetDefaultGatewayIPv4();
        var candidates = new List<IPAddress>();

        if (gateway != null)
        {
            var bytes = gateway.GetAddressBytes();
            if (bytes.Length == 4)
            {
                for (int i = 1; i <= 254; i++)
                {
                    if (i == bytes[3]) continue;
                    candidates.Add(new IPAddress(new byte[] { bytes[0], bytes[1], bytes[2], (byte)i }));
                }
            }
        }

        var arpIps = GetArpCacheIPs().ToList();
        foreach (var ip in arpIps)
            if (!candidates.Contains(ip)) candidates.Add(ip);

        candidates = candidates
            .Distinct()
            .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            .Take(Math.Max(1, maxHostsToProbe))
            .ToList();

        var results = new List<NetworkDevice>();

        // Include gateway first
        if (gateway != null)
        {
            results.Add(new NetworkDevice
            {
                Ip = gateway.ToString(),
                Hostname = "Gateway",
            });
        }

        foreach (var ip in candidates)
        {
            if (gateway != null && ip.Equals(gateway))
                continue;

            bool alive = false;
            try
            {
                using var ping = new Ping();
                var reply = ping.Send(ip, timeoutMs);
                alive = reply != null && reply.Status == IPStatus.Success;
            }
            catch
            {
                alive = false;
            }

            if (!alive)
                continue;

            results.Add(new NetworkDevice
            {
                Ip = ip.ToString(),
            });
        }

        // Attach MACs from ARP cache
        var arp = GetArpCache();
        foreach (var d in results)
        {
            if (arp.TryGetValue(d.Ip, out var mac))
                d.Mac = mac;
        }

        // Best-effort: Hostname + VendorHint
        FillHostnamesBestEffort(results, perHostTimeoutMs: 250);
        FillVendorHints(results);

        // Keep gateway first (if present)
        return results
            .OrderByDescending(x => gateway != null && string.Equals(x.Ip, gateway.ToString(), StringComparison.OrdinalIgnoreCase))
            .ThenBy(x => x.Ip, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public IPAddress? GetDefaultGatewayIPv4()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                var props = ni.GetIPProperties();
                var gw = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a != null &&
                                         a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                                         !IPAddress.IsLoopback(a));

                if (gw != null)
                    return gw;
            }
        }
        catch { }
        return null;
    }

    private void FillHostnamesBestEffort(IReadOnlyList<NetworkDevice> devices, int perHostTimeoutMs)
    {
        foreach (var d in devices)
        {
            if (!string.IsNullOrWhiteSpace(d.Hostname))
                continue;

            if (!IPAddress.TryParse(d.Ip, out var ip))
                continue;

            // Avoid blocking UI: keep it short and best-effort
            try
            {
                var name = ResolveReverseDnsWithTimeout(ip, perHostTimeoutMs);
                if (!string.IsNullOrWhiteSpace(name))
                    d.Hostname = name;
            }
            catch
            {
                // ignore
            }
        }
    }

    private static string? ResolveReverseDnsWithTimeout(IPAddress ip, int timeoutMs)
    {
        try
        {
            var task = Task.Run(() =>
            {
                try
                {
                    var entry = Dns.GetHostEntry(ip);
                    var hn = entry?.HostName;
                    if (string.IsNullOrWhiteSpace(hn)) return null;

                    // normalize "host." endings
                    hn = hn.Trim().TrimEnd('.');
                    return hn;
                }
                catch
                {
                    return null;
                }
            });

            var done = Task.WhenAny(task, Task.Delay(timeoutMs)).GetAwaiter().GetResult();
            if (done != task) return null;

            return task.GetAwaiter().GetResult();
        }
        catch
        {
            return null;
        }
    }

    private void FillVendorHints(IReadOnlyList<NetworkDevice> devices)
    {
        foreach (var d in devices)
        {
            if (!string.IsNullOrWhiteSpace(d.VendorHint))
                continue;

            var oui = GetOuiPrefix(d.Mac);
            if (oui == null) continue;

            if (OuiVendors.TryGetValue(oui, out var vendor))
                d.VendorHint = vendor;
        }
    }

    private static string? GetOuiPrefix(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return null;

        // mac expected like "aa:bb:cc:dd:ee:ff"
        var s = mac.Trim().ToLowerInvariant().Replace("-", ":");
        var parts = s.Split(':', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return null;

        // validate hex-ish quickly
        if (parts[0].Length != 2 || parts[1].Length != 2 || parts[2].Length != 2) return null;

        return $"{parts[0]}:{parts[1]}:{parts[2]}";
    }

    // Minimal starter set, bővíthetjük folyamatosan
    private static readonly Dictionary<string, string> OuiVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        // TP-Link (gyakori)
        ["a0:ab:1b"] = "TP-Link",
        ["50:c7:bf"] = "TP-Link",

        // Apple (példák, nem teljes)
        ["a4:5e:60"] = "Apple",
        ["d0:23:db"] = "Apple",

        // Samsung (példák)
        ["d8:bb:2c"] = "Samsung",
        ["30:07:4d"] = "Samsung",

        // Xiaomi (példák)
        ["3c:cd:5d"] = "Xiaomi",

        // Huawei (példák)
        ["f4:6a:dd"] = "Huawei",

        // Google/Nest (példák)
        ["f4:f5:d8"] = "Google",

        // Microsoft/Xbox (példák)
        ["7c:1e:52"] = "Microsoft",

        // Sony/PlayStation (példák)
        ["0c:fe:45"] = "Sony",
    };

    private IEnumerable<IPAddress> GetArpCacheIPs()
    {
        foreach (var kv in GetArpCache())
        {
            if (IPAddress.TryParse(kv.Key, out var ip))
                yield return ip;
        }
    }

    private Dictionary<string, string> GetArpCache()
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "arp",
                Arguments = "-a",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };

            using var p = System.Diagnostics.Process.Start(psi);
            if (p == null) return dict;

            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);

            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var s = line.Trim();
                if (s.Length == 0) continue;
                if (!char.IsDigit(s[0])) continue;

                var parts = s.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                var ip = parts[0].Trim();
                var mac = parts[1].Trim();

                if (IPAddress.TryParse(ip, out _))
                {
                    mac = mac.Replace('-', ':').ToLowerInvariant();
                    dict[ip] = mac;
                }
            }
        }
        catch { }

        return dict;
    }
}
