using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

/// <summary>Explicit, rate-limited local echo refresh. No ports, DNS names, router access or config writes.</summary>
public static class LanDiscoveryRefresh
{
    private static readonly SemaphoreSlim Gate = new(1,1);
    private static DateTimeOffset LastRefresh;
    public static string LastReport { get; private set; } = "Passive host evidence only; visibility is incomplete.";
    public static string[] Targets(IPAddress address, int prefixLength)
    {
        // Never truncate a large subnet to an arbitrary first set of hosts; report passive-only instead.
        if(address.AddressFamily!=AddressFamily.InterNetwork || prefixLength<24 || prefixLength>30 || IPAddress.IsLoopback(address))return [];
        var b=address.GetAddressBytes();uint value=((uint)b[0]<<24)|((uint)b[1]<<16)|((uint)b[2]<<8)|b[3];
        var mask=uint.MaxValue<<(32-prefixLength);var network=value&mask;var count=1u<<(32-prefixLength);
        return Enumerable.Range(1,(int)count-2).Select(i=>network+(uint)i).Where(v=>v!=value)
            .Select(v=>new IPAddress(new byte[]{(byte)(v>>24),(byte)(v>>16),(byte)(v>>8),(byte)v}).ToString()).ToArray();
    }
    public static async Task<NetworkIdentityEvidence[]> RefreshAsync(CancellationToken cancellationToken=default)
    {
        if(!await Gate.WaitAsync(0,cancellationToken))return PassiveIdentityEvidence.Read();
        try
        {
            if(DateTimeOffset.UtcNow-LastRefresh<TimeSpan.FromMinutes(1))return PassiveIdentityEvidence.Read();
            LastRefresh=DateTimeOffset.UtcNow;
            using var limit=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);limit.CancelAfter(TimeSpan.FromSeconds(6));
            var adapters=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211).Take(4).ToArray();
            var targets=adapters.SelectMany(n=>n.GetIPProperties().UnicastAddresses.SelectMany(a=>Targets(a.Address,a.PrefixLength))).Distinct().Take(254).ToArray();
            var successful=0;var unavailable=0;var unanswered=0;
            using var workers=new SemaphoreSlim(16);
            await Task.WhenAll(targets.Select(async target=>
            {
                await workers.WaitAsync(limit.Token);
                try {using var ping=new Ping();var reply=await ping.SendPingAsync(target,180);if(reply.Status==IPStatus.Success)Interlocked.Increment(ref successful);else Interlocked.Increment(ref unanswered);}
                catch(Exception e) when(e is PingException or SocketException or InvalidOperationException) {Interlocked.Increment(ref unavailable);}
                finally {workers.Release();}
            }));
            LastReport=$"Bounded local IPv4 echo: {targets.Length} targets, {successful} replies, {unanswered} unanswered, {unavailable} unavailable. No response is not proof of absence. Large subnets remain passive-only.";
            // An ordinary scoped ICMPv6 echo can enrich NDP. Devices may legitimately not answer.
            if(OperatingSystem.IsLinux()) foreach(var adapter in adapters.Where(n=>n.GetIPProperties().UnicastAddresses.Any(a=>a.Address.IsIPv6LinkLocal)).Take(2))
            {
                try
                {
                    using var p=new System.Diagnostics.Process {StartInfo=new("ping") {UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true}};
                    foreach(var arg in new[]{"-6","-n","-c","1","-W","1","-I",adapter.Name,"ff02::1"})p.StartInfo.ArgumentList.Add(arg);
                    p.Start();var output=p.StandardOutput.ReadToEndAsync();var error=p.StandardError.ReadToEndAsync();
                    try {await p.WaitForExitAsync(limit.Token);LastReport+=$" IPv6 scoped echo exit {p.ExitCode}.";}catch(OperationCanceledException){p.Kill(true);LastReport+=" IPv6 echo deadline reached.";break;}
                }
                catch(Exception e) when(e is System.ComponentModel.Win32Exception or InvalidOperationException) {LastReport+=" IPv6 echo unavailable.";}
            }
        }
        catch(OperationCanceledException) {LastReport="Bounded discovery refresh cancelled/deadline reached; passive evidence retained.";}
        finally {Gate.Release();}
        PassiveIdentityEvidence.Invalidate();
        return PassiveIdentityEvidence.Read();
    }
}
