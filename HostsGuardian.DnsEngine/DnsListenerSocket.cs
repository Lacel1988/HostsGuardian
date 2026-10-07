using System.Net;
using System.Net.Sockets;
namespace HostsGuardian.DnsEngine;

/// <summary>One dual-mode socket shares admission limits and processing across both families.
/// If IPv6 binding fails, retain IPv4 service and publish the IPv6 fault explicitly.</summary>
internal static class DnsListenerSocket
{
    internal static (Socket Socket, string Ipv6State) Bind(SocketType type, int port, bool enableIpv6)
    {
        var state = !enableIpv6 ? "Disabled" : !Socket.OSSupportsIPv6 ? "NotApplicable" : "Faulted";
        if (enableIpv6 && Socket.OSSupportsIPv6)
        {
            var dual = new Socket(AddressFamily.InterNetworkV6, type, type == SocketType.Dgram ? ProtocolType.Udp : ProtocolType.Tcp);
            try
            {
                dual.ExclusiveAddressUse = true;
                dual.DualMode = true;
                dual.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                return (dual, "Listening");
            }
            catch (SocketException) { dual.Dispose(); EngineLog.Warning("DNS", "IPv6 binding unavailable; IPv4 fallback will report degraded capability"); }
            catch { dual.Dispose(); throw; }
        }
        var ipv4 = new Socket(AddressFamily.InterNetwork, type, type == SocketType.Dgram ? ProtocolType.Udp : ProtocolType.Tcp);
        try { ipv4.ExclusiveAddressUse = true; ipv4.Bind(new IPEndPoint(IPAddress.Any, port)); return (ipv4, state); }
        catch { ipv4.Dispose(); throw; }
    }
}
