using HostsGuardian.Wpf.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HostsGuardian.Core.Services
{
    public sealed class RouterDetectionService
    {
        public async Task<RouterDetectionResult> DetectAsync(CancellationToken ct)
        {
            var res = new RouterDetectionResult();

            // 1) Find "best" active interface (Up, not loopback) that has a gateway.
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(n => new
                {
                    Nic = n,
                    Props = n.GetIPProperties()
                })
                .Where(x => x.Props.GatewayAddresses.Any(g => g.Address != null && g.Address.AddressFamily == AddressFamily.InterNetwork))
                .OrderByDescending(x => x.Props.UnicastAddresses.Count(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
                .FirstOrDefault();

            if (nic == null)
            {
                res.Notes = "No active network interface with IPv4 gateway was found.";
                return res;
            }

            res.InterfaceName = nic.Nic.Name;

            var ipv4 = nic.Props.UnicastAddresses
                .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
            if (ipv4 != null) res.LocalIp = ipv4.ToString();

            var gw = nic.Props.GatewayAddresses
                .FirstOrDefault(g => g.Address != null && g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
            if (gw != null) res.GatewayIp = gw.ToString();

            var dns = nic.Props.DnsAddresses
                .Where(d => d.AddressFamily == AddressFamily.InterNetwork || d.AddressFamily == AddressFamily.InterNetworkV6)
                .Select(d => d.ToString())
                .ToList();
            res.DnsServers = dns.Count == 0 ? "(none)" : string.Join(", ", dns);

            // 2) Try Wi-Fi SSID (best-effort, can fail on non-wifi)
            res.WifiSsid = TryGetWifiSsid() ?? "";

            // 3) Router candidates: HTTP fingerprint + SSDP hints (both safe, best-effort)
            var candidates = new List<RouterCandidate>();

            if (!string.IsNullOrWhiteSpace(res.GatewayIp))
            {
                var http = await TryHttpFingerprintAsync(res.GatewayIp, ct);
                candidates.AddRange(http);

                var ssdp = await TrySsdpAsync(ct);
                candidates.AddRange(ssdp);
            }

            // Merge candidates by name (keep best confidence)
            res.Candidates = candidates
                .GroupBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var best = g.OrderByDescending(x => x.Confidence).First();
                    best.Evidence = string.Join(" | ", g.Select(x => x.Evidence).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());
                    return best;
                })
                .OrderByDescending(c => c.Confidence)
                .Take(8)
                .ToList();

            if (res.Candidates.Count == 0)
                res.Notes = "Gateway detected, but router brand fingerprint is unknown (this is normal on many networks).";

            return res;
        }

        private static string? TryGetWifiSsid()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show interfaces",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var p = Process.Start(psi);
                if (p == null) return null;

                var text = p.StandardOutput.ReadToEnd();
                p.WaitForExit(2000);

                // Works on many locales: look for "SSID" line (avoid BSSID)
                var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    // e.g. "SSID                   : MyWifi"
                    if (trimmed.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("SSID name", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = trimmed.IndexOf(':');
                        if (idx >= 0 && idx + 1 < trimmed.Length)
                            return trimmed[(idx + 1)..].Trim();
                    }
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private static async Task<List<RouterCandidate>> TryHttpFingerprintAsync(string gatewayIp, CancellationToken ct)
        {
            var list = new List<RouterCandidate>();

            try
            {
                using var http = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(2.5)
                };

                // Many routers respond on http://gateway/
                var url = "http://" + gatewayIp + "/";
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

                var server = resp.Headers.Server?.ToString() ?? "";
                var headers = resp.Headers.ToString();

                var snippet = "";
                try
                {
                    var body = await resp.Content.ReadAsStringAsync(ct);
                    snippet = body.Length > 6000 ? body[..6000] : body;
                }
                catch { /* ignore body read */ }

                var hay = (server + "\n" + headers + "\n" + snippet).ToLowerInvariant();

                // Heuristic keywords -> candidates
                AddIfMatch(list, hay, "fritz", "AVM FRITZ!Box", 85, "HTTP fingerprint contains 'fritz'");
                AddIfMatch(list, hay, "asuswrt", "ASUS (ASUSWRT)", 85, "HTTP fingerprint contains 'asuswrt'");
                AddIfMatch(list, hay, "mikrotik", "MikroTik (RouterOS)", 80, "HTTP fingerprint contains 'mikrotik'");
                AddIfMatch(list, hay, "routeros", "MikroTik (RouterOS)", 80, "HTTP fingerprint contains 'routeros'");
                AddIfMatch(list, hay, "openwrt", "OpenWrt", 78, "HTTP fingerprint contains 'openwrt'");
                AddIfMatch(list, hay, "tplink", "TP-Link", 75, "HTTP fingerprint contains 'tplink'");
                AddIfMatch(list, hay, "tenda", "Tenda", 72, "HTTP fingerprint contains 'tenda'");
                AddIfMatch(list, hay, "d-link", "D-Link", 72, "HTTP fingerprint contains 'd-link'");
                AddIfMatch(list, hay, "zyxel", "Zyxel", 72, "HTTP fingerprint contains 'zyxel'");
                AddIfMatch(list, hay, "huawei", "Huawei", 70, "HTTP fingerprint contains 'huawei'");
                AddIfMatch(list, hay, "ubiquiti", "Ubiquiti (UniFi/Edge)", 76, "HTTP fingerprint contains 'ubiquiti'");
                AddIfMatch(list, hay, "unifi", "Ubiquiti (UniFi/Edge)", 76, "HTTP fingerprint contains 'unifi'");
            }
            catch
            {
                // totally fine
            }

            return list;
        }

        private static void AddIfMatch(List<RouterCandidate> list, string hay, string needle, string name, int conf, string evidence)
        {
            if (hay.Contains(needle))
                list.Add(new RouterCandidate { Name = name, Confidence = conf, Evidence = evidence });
        }

        private static async Task<List<RouterCandidate>> TrySsdpAsync(CancellationToken ct)
        {
            // SSDP is a best-effort. Some networks block multicast, that's ok.
            var list = new List<RouterCandidate>();

            try
            {
                using var udp = new UdpClient(AddressFamily.InterNetwork);
                udp.Client.ReceiveTimeout = 1200;

                var msg =
                    "M-SEARCH * HTTP/1.1\r\n" +
                    "HOST: 239.255.255.250:1900\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 1\r\n" +
                    "ST: ssdp:all\r\n\r\n";

                var data = Encoding.UTF8.GetBytes(msg);
                var ep = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);

                await udp.SendAsync(data, data.Length, ep);

                var start = DateTime.UtcNow;
                while ((DateTime.UtcNow - start).TotalMilliseconds < 1200 && !ct.IsCancellationRequested)
                {
                    UdpReceiveResult r;
                    try
                    {
                        r = await udp.ReceiveAsync(ct);
                    }
                    catch
                    {
                        break;
                    }

                    var txt = Encoding.UTF8.GetString(r.Buffer);
                    var low = txt.ToLowerInvariant();

                    // Some common hints
                    if (low.Contains("fritz"))
                        list.Add(new RouterCandidate { Name = "AVM FRITZ!Box", Confidence = 70, Evidence = "SSDP response contains 'fritz'" });

                    if (low.Contains("openwrt"))
                        list.Add(new RouterCandidate { Name = "OpenWrt", Confidence = 68, Evidence = "SSDP response contains 'openwrt'" });

                    if (low.Contains("mikrotik") || low.Contains("routeros"))
                        list.Add(new RouterCandidate { Name = "MikroTik (RouterOS)", Confidence = 65, Evidence = "SSDP response contains 'mikrotik/routeros'" });

                    if (low.Contains("upnp") && low.Contains("igdd"))
                        list.Add(new RouterCandidate { Name = "Generic UPnP IGD Router", Confidence = 55, Evidence = "SSDP hints IGD device" });
                }
            }
            catch
            {
                // ignore
            }

            return list;
        }
    }
}
