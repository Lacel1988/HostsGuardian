using HostsGuardian.Core.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace HostsGuardian.Core.Services;

public sealed class NetworkScanService
{
    public List<DeviceInfo> ScanLanBestEffort(int maxHostsToProbe = 96, int timeoutMs = 140)
    {
        var (gateway, localIp) = GetGatewayAndLocalIp();
        if (string.IsNullOrWhiteSpace(gateway) || string.IsNullOrWhiteSpace(localIp))
            return new List<DeviceInfo>();

        var prefix = Get24Prefix(localIp);
        if (string.IsNullOrWhiteSpace(prefix))
            return new List<DeviceInfo>();

        // 1) ping sweep (kicsi, gyors, nem bánt semmit)
        var ips = Enumerable.Range(1, Math.Min(254, maxHostsToProbe))
            .Select(i => prefix + i.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var online = new List<(string ip, int ms)>();

        var sem = new SemaphoreSlim(24);
        var tasks = ips.Select(async ip =>
        {
            await sem.WaitAsync().ConfigureAwait(false);
            try
            {
                using var p = new Ping();
                var reply = await p.SendPingAsync(ip, timeoutMs).ConfigureAwait(false);
                if (reply.Status == IPStatus.Success)
                {
                    lock (online)
                        online.Add((ip, (int)reply.RoundtripTime));
                }
            }
            catch { }
            finally { sem.Release(); }
        }).ToArray();

        Task.WaitAll(tasks, TimeSpan.FromSeconds(10));

        // 2) friss ARP táblából MAC-ek
        var arp = ReadArpTable();

        // 3) reverse DNS hostname best effort
        var results = new List<DeviceInfo>();

        foreach (var (ip, ms) in online.OrderBy(x => x.ip, StringComparer.OrdinalIgnoreCase))
        {
            arp.TryGetValue(ip, out var mac);

            var hostname = TryReverseDns(ip);

            results.Add(new DeviceInfo
            {
                Ip = ip,
                Mac = mac ?? "",
                Hostname = hostname ?? "",
                IsOnline = true,
                PingMs = ms
            });
        }

        // router/gateway is látszódjon akkor is, ha nem válaszolt pingre
        if (!results.Any(x => x.Ip == gateway))
        {
            arp.TryGetValue(gateway, out var mac);
            results.Insert(0, new DeviceInfo
            {
                Ip = gateway,
                Mac = mac ?? "",
                Hostname = "Gateway",
                IsOnline = true,
                PingMs = -1
            });
        }

        return results;
    }

    private static string? TryReverseDns(string ip)
    {
        try
        {
            return ResolveHostnameAsync(ip, TimeSpan.FromMilliseconds(250)).GetAwaiter().GetResult();
        }
        catch { return ""; }
    }

    public static async Task<string> ResolveHostnameAsync(string ip, TimeSpan timeout,
        Func<string, CancellationToken, Task<IPHostEntry>>? lookup = null)
    {
        using var deadline = new CancellationTokenSource(timeout);
        try
        {
            lookup ??= (address, ct) => Dns.GetHostEntryAsync(address, System.Net.Sockets.AddressFamily.Unspecified, ct);
            var entry = await lookup(ip, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
            return (entry.HostName ?? "").Trim().TrimEnd('.');
        }
        catch (OperationCanceledException) { return ""; }
        catch (System.Net.Sockets.SocketException) { return ""; }
        catch (ArgumentException) { return ""; }
    }

    private static Dictionary<string, string> ReadArpTable()
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "arp",
                Arguments = "-a",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi);
            if (p == null) return dict;

            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);

            // arp -a (Windows) tipikus sor:
            //  192.168.1.1           40-c2-ba-xx-xx-xx     dynamic
            var rx = new Regex(@"\b(?<ip>\d{1,3}(\.\d{1,3}){3})\s+(?<mac>([0-9a-f]{2}-){5}[0-9a-f]{2})\b",
                RegexOptions.IgnoreCase);

            foreach (Match m in rx.Matches(text))
            {
                var ip = m.Groups["ip"].Value.Trim();
                var mac = m.Groups["mac"].Value.Trim().ToLowerInvariant();
                if (!dict.ContainsKey(ip)) dict[ip] = mac;
            }
        }
        catch { }

        return dict;
    }

    private static (string gateway, string localIp) GetGatewayAndLocalIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var ipProps = ni.GetIPProperties();
                var gw = ipProps.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                var ip = ipProps.UnicastAddresses
                    .Select(u => u.Address)
                    .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                if (gw != null && ip != null)
                    return (gw.ToString(), ip.ToString());
            }
        }
        catch { }

        return ("", "");
    }

    private static string Get24Prefix(string ip)
    {
        // 192.168.1.52 -> 192.168.1.
        var parts = (ip ?? "").Split('.');
        if (parts.Length != 4) return "";
        return $"{parts[0]}.{parts[1]}.{parts[2]}.";
    }
}