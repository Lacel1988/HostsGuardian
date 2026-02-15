using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace HostsGuardian.Wpf.Services
{
    public sealed class RouterDetectService
    {
        public RouterDetectResult Detect()
        {
            // Pick first "best" interface: Up + has IPv4 + has gateway
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up)
                         .OrderByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                         .ThenByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
            {
                var props = ni.GetIPProperties();
                var gw = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a != null && a.AddressFamily == AddressFamily.InterNetwork);

                var uni = props.UnicastAddresses
                    .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);

                if (uni == null) continue;

                // Gateway can be null on some setups; still return adapter + local ip
                return new RouterDetectResult
                {
                    AdapterName = ni.Name,
                    LocalIpv4 = uni.Address.ToString(),
                    SubnetMaskIpv4 = uni.IPv4Mask?.ToString(),
                    GatewayIpv4 = gw?.ToString()
                };
            }

            return RouterDetectResult.Empty();
        }

        public string BuildSnapshotText(RouterDetectResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Router detection (info-only)");
            sb.AppendLine("---------------------------");
            sb.AppendLine($"Adapter: {r.AdapterName ?? "(unknown)"}");
            sb.AppendLine($"Local IPv4: {r.LocalIpv4 ?? "(unknown)"}");
            sb.AppendLine($"Subnet mask: {r.SubnetMaskIpv4 ?? "(unknown)"}");
            sb.AppendLine($"Gateway: {r.GatewayIpv4 ?? "(unknown)"}");
            sb.AppendLine();
            sb.AppendLine("Notes:");
            sb.AppendLine("- Wi-Fi is fine; gateway detection does NOT require Ethernet cable.");
            sb.AppendLine("- Device list is best-effort (ping + ARP). Some devices won't show until active.");
            return sb.ToString();
        }
    }

    public sealed class RouterDetectResult
    {
        public string? AdapterName { get; set; }
        public string? LocalIpv4 { get; set; }
        public string? SubnetMaskIpv4 { get; set; }
        public string? GatewayIpv4 { get; set; }

        public static RouterDetectResult Empty() => new();
    }
}
