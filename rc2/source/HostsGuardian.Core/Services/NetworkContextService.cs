using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace HostsGuardian.Core.Services;

public sealed record NetworkContext(string State, string? Fingerprint, string WifiIdentity, int ActiveInterfaces);
/// <summary>Read-only best-effort context, not authenticated device or Wi-Fi identity.</summary>
public static class NetworkContextService
{
    public static NetworkContext Read()
    {
        try
        {
            var active = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback).ToArray();
            var evidence = active.SelectMany(n => n.GetIPProperties().GatewayAddresses
                .Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(g => n.Id + ":" + g.Address)).Distinct().Order(StringComparer.Ordinal).ToArray();
            if (evidence.Length == 0) return new("Unknown", null, "Unknown", active.Length);
            return new("BestEffort", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("|", evidence)))), "Unknown", active.Length);
        }
        catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException or System.Security.SecurityException or UnauthorizedAccessException)
        { return new("Unknown", null, "Unknown", 0); }
    }
}
