using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services
{
    public sealed class DeviceDiscoveryService
    {
        // Egyszerű vendor tipp (MAC prefix alapján). Nem tökéletes, de hasznos.
        private static readonly Dictionary<string, string> VendorByOui = new(StringComparer.OrdinalIgnoreCase)
        {
            { "F0-99-B6", "Apple" },
            { "3C-5A-B4", "Google" },
            { "D8-96-95", "Samsung" },
            { "A4-34-D9", "Xiaomi" },
            { "BC-92-6B", "LG" },
        };

        public List<NetworkDevice> Discover()
        {
            // 1) Pingeljük meg a gateway-t és néhány címet, hogy frissüljön az ARP tábla
            try { WarmUpArp(); } catch { /* nem kritikus */ }

            // 2) arp -a parse
            var arpText = Run("arp", "-a");
            var list = ParseArp(arpText);

            // 3) Hostname reverse lookup (óvatosan, lassú lehet)
            foreach (var d in list)
            {
                d.VendorHint = GuessVendor(d.Mac);
                d.Hostname = TryReverseDns(d.Ip) ?? "";
            }

            // Szűrés: csak értelmes MAC + IPv4
            return list
                .Where(x => !string.IsNullOrWhiteSpace(x.Ip) && !string.IsNullOrWhiteSpace(x.Mac))
                .OrderBy(x => x.Ip)
                .ToList();
        }

        private static void WarmUpArp()
        {
            // Pingeljük a default gateway-t + néhány közeli címet (nagyon light)
            var gw = GetDefaultGateway();
            if (gw != null)
                TryPing(gw.ToString());

            // pár cím a saját subnetből
            var local = GetLocalIPv4();
            if (local != null)
            {
                var prefix = GetPrefix24(local.ToString());
                for (int i = 1; i <= 10; i++)
                    TryPing(prefix + i);
            }
        }

        private static IPAddress? GetDefaultGateway()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                var props = ni.GetIPProperties();
                foreach (var g in props.GatewayAddresses)
                {
                    if (g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        return g.Address;
                }
            }
            return null;
        }

        private static IPAddress? GetLocalIPv4()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                var props = ni.GetIPProperties();
                foreach (var ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var ip = ua.Address.ToString();
                        if (ip.StartsWith("169.254.")) continue; // APIPA
                        return ua.Address;
                    }
                }
            }
            return null;
        }

        private static string GetPrefix24(string ip)
        {
            var parts = ip.Split('.');
            if (parts.Length != 4) return "";
            return $"{parts[0]}.{parts[1]}.{parts[2]}.";
        }

        private static void TryPing(string ip)
        {
            try
            {
                using var p = new Ping();
                p.Send(ip, 200);
            }
            catch { }
        }

        private static string Run(string file, string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return "";
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(1500);
            return text ?? "";
        }

        private static List<NetworkDevice> ParseArp(string arpText)
        {
            // Windows arp -a tipikus sor:
            //  192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
            var rx = new Regex(@"(?<ip>\d{1,3}(\.\d{1,3}){3})\s+(?<mac>([0-9a-f]{2}-){5}[0-9a-f]{2})",
                RegexOptions.IgnoreCase);

            var list = new List<NetworkDevice>();
            foreach (Match m in rx.Matches(arpText))
            {
                var ip = m.Groups["ip"].Value.Trim();
                var mac = m.Groups["mac"].Value.Trim().ToUpperInvariant();

                list.Add(new NetworkDevice
                {
                    Ip = ip,
                    Mac = mac
                });
            }
            return list;
        }

        private static string GuessVendor(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac) || mac.Length < 8) return "";
            var oui = mac.Substring(0, 8); // "AA-BB-CC"
            return VendorByOui.TryGetValue(oui, out var v) ? v : "";
        }

        private static string? TryReverseDns(string ip)
        {
            try
            {
                var entry = Dns.GetHostEntry(ip);
                return entry?.HostName;
            }
            catch
            {
                return null;
            }
        }
    }
}
