using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

/// <summary>Bounded passive host evidence. No DNS queries, router access or configuration writes.
/// Cached host DHCPv6 data is explicitly not current RA/RDNSS or another client's resolver selection.</summary>
public static class DnsCoverageEvidence
{
    private static readonly object Gate = new();
    private static DateTimeOffset ReadAt;
    private static DnsCoverage Cached = new();
    public static DnsCoverage Read()
    {
        lock(Gate)
        {
            if(DateTimeOffset.UtcNow-ReadAt<TimeSpan.FromSeconds(30)) return Cached;
            ReadAt=DateTimeOffset.UtcNow;
            try
            {
                var interfaces=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback).Take(64).ToArray();
                var active=interfaces.Any(n=>n.GetIPProperties().UnicastAddresses.Any(a=>a.Address.AddressFamily==AddressFamily.InterNetworkV6 && !a.Address.IsIPv6LinkLocal && !IPAddress.IsLoopback(a.Address)));
                var resolvers=new HashSet<string>();
                if(OperatingSystem.IsLinux()) foreach(var nic in interfaces)
                {
                    var index=nic.GetIPProperties().GetIPv6Properties()?.Index;
                    if(index==null)continue;
                    var path="/run/NetworkManager/devices/"+index;
                    try
                    {
                        var info=new FileInfo(path);if(!info.Exists || info.LinkTarget!=null || info.Length>16384)continue;
                        using var stream=File.OpenRead(path);var bytes=new byte[16385];var count=stream.Read(bytes);if(count>16384)continue;
                        var text=System.Text.Encoding.UTF8.GetString(bytes,0,count);
                        if(!text.Split('\n').Any(line=>line.Trim()=="managed=true"))continue;
                        foreach(var line in text.Split('\n').Where(line=>line.StartsWith("dhcp6.dhcp6_name_servers=")))
                            foreach(var item in line.Split('=',2)[1].Split(new[]{' ',',',';'},StringSplitOptions.RemoveEmptyEntries).Take(16))
                                if(IPAddress.TryParse(item,out var address) && address.AddressFamily==AddressFamily.InterNetworkV6 && resolvers.Count<16)resolvers.Add(address.ToString());
                    }
                    catch(Exception e) when(e is IOException or UnauthorizedAccessException) { }
                }
                Cached=new() {HostIpv6Active=active,HostCachedIpv6Resolvers=resolvers.Order().ToArray(),
                    HostEvidence="OBSERVED: local OS IPv6 addresses; cached Engine-host DHCPv6 lease when available. Current RA/RDNSS and client resolver selection remain unknown."};
            }
            catch(Exception e) when(e is NetworkInformationException or PlatformNotSupportedException or UnauthorizedAccessException or System.Security.SecurityException) { Cached=new(); }
            return Cached;
        }
    }
}
