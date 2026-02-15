using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;

namespace HostsGuardian.Wpf.Services
{
    public sealed class RouterSnapshotService
    {
        public RouterDetectionResult Detect()
        {
            var sb = new StringBuilder();

            var gateway = TryGetGatewayFromNetworkInterfaces();
            if (gateway == null)
                gateway = TryGetGatewayFromRoutePrint();
            if (gateway == null)
                gateway = TryGetGatewayFromIpConfig();

            sb.AppendLine("Router detection (info-only)");
            sb.AppendLine("--------------------------------");
            sb.AppendLine("Default gateway: " + (gateway ?? "(not found)"));
            sb.AppendLine();

            sb.AppendLine("Active interfaces:");
            foreach (var line in GetInterfacesSummary())
                sb.AppendLine(" - " + line);

            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(gateway))
            {
                sb.AppendLine();
                sb.AppendLine("ARP table (filtered):");
                var arpIps = GetArpIps()
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                // gateway első helyre
                candidates.Add(gateway);

                foreach (var ip in arpIps)
                {
                    if (string.Equals(ip, gateway, StringComparison.OrdinalIgnoreCase))
                        continue;
                    candidates.Add(ip);
                }

                // snapshotba csak néhány sor
                foreach (var ip in candidates.Take(25))
                    sb.AppendLine(" - " + ip);

                if (candidates.Count > 25)
                    sb.AppendLine(" - ... (" + candidates.Count + " total)");
            }
            else
            {
                sb.AppendLine();
                sb.AppendLine("Candidates: (none) because default gateway was not detected.");
            }

            return new RouterDetectionResult
            {
                SnapshotText = sb.ToString(),
                DefaultGateway = gateway,
                Candidates = candidates
            };
        }

        private static IEnumerable<string> GetInterfacesSummary()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var props = ni.GetIPProperties();
                var ipv4 = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .ToList();

                var gw = props.GatewayAddresses
                    .Select(g => g.Address)
                    .Where(a => a != null)
                    .Select(a => a!.ToString())
                    .ToList();

                yield return $"{ni.Name} | IPv4: {(ipv4.Count == 0 ? "-" : string.Join(", ", ipv4))} | GW: {(gw.Count == 0 ? "-" : string.Join(", ", gw))}";
            }
        }

        private static string? TryGetGatewayFromNetworkInterfaces()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up)
                        continue;

                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    var props = ni.GetIPProperties();

                    // legyen IPv4 címe
                    var hasIpv4 = props.UnicastAddresses.Any(a =>
                        a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                    if (!hasIpv4)
                        continue;

                    var gw = props.GatewayAddresses
                        .Select(g => g.Address)
                        .FirstOrDefault(a =>
                            a != null &&
                            a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                            !a.Equals(IPAddress.Any));

                    if (gw != null)
                        return gw.ToString();
                }
            }
            catch { }

            return null;
        }

        private static string? TryGetGatewayFromRoutePrint()
        {
            // route print -4 -> 0.0.0.0 0.0.0.0 <gateway> <interface> <metric>
            var text = RunCmd("route", "print -4");
            if (string.IsNullOrWhiteSpace(text))
                return null;

            foreach (var line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("0.0.0.0"))
                    continue;

                // normalizáljuk a whitespace-t
                var parts = Regex.Split(trimmed, @"\s+").Where(p => p.Length > 0).ToArray();
                if (parts.Length < 3)
                    continue;

                // parts[0]=0.0.0.0, parts[1]=0.0.0.0, parts[2]=gateway
                if (IPAddress.TryParse(parts[2], out var gw))
                    return gw.ToString();
            }

            return null;
        }

        private static string? TryGetGatewayFromIpConfig()
        {
            // ipconfig -> "Default Gateway . . . . . . . . . : 192.168.1.1"
            var text = RunCmd("ipconfig", "");
            if (string.IsNullOrWhiteSpace(text))
                return null;

            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            foreach (var line in lines)
            {
                if (!line.Contains("Default Gateway", StringComparison.OrdinalIgnoreCase))
                    continue;

                var idx = line.IndexOf(':');
                if (idx < 0)
                    continue;

                var right = line[(idx + 1)..].Trim();
                if (IPAddress.TryParse(right, out var gw))
                    return gw.ToString();
            }

            return null;
        }

        private static IEnumerable<string> GetArpIps()
        {
            var text = RunCmd("arp", "-a");
            if (string.IsNullOrWhiteSpace(text))
                yield break;

            foreach (var line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                // tipikus: "192.168.1.1           11-22-33-44-55-66     dynamic"
                var parts = Regex.Split(trimmed, @"\s+").Where(p => p.Length > 0).ToArray();
                if (parts.Length < 1)
                    continue;

                if (IPAddress.TryParse(parts[0], out var ip) &&
                    ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    yield return ip.ToString();
                }
            }
        }

        private static string RunCmd(string fileName, string args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var p = Process.Start(psi);
                if (p == null) return "";

                var output = p.StandardOutput.ReadToEnd();
                var err = p.StandardError.ReadToEnd();

                p.WaitForExit(4000);

                // ha az output üres, de az error nem, akkor legalább látszódjon valami
                if (string.IsNullOrWhiteSpace(output) && !string.IsNullOrWhiteSpace(err))
                    return err;

                return output;
            }
            catch
            {
                return "";
            }
        }
    }

    public sealed class RouterDetectionResult
    {
        public string SnapshotText { get; set; } = "";
        public string? DefaultGateway { get; set; }
        public List<string> Candidates { get; set; } = new();
    }
}
