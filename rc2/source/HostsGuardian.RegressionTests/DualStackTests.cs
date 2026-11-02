using System.Net;
using System.Net.Sockets;
using System.Text;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;
internal static class DualStackTests
{
    static void Check(bool value,string message) { if(!value) throw new Exception(message); }
    static byte[] Query(string name)
    {
        var data=new List<byte>{0x12,0x34,1,0,0,1,0,0,0,0,0,0};
        foreach(var label in name.Split('.')) {data.Add((byte)label.Length);data.AddRange(Encoding.ASCII.GetBytes(label));}
        data.AddRange(new byte[]{0,0,1,0,1});return data.ToArray();
    }
    static int Port() { var socket=new TcpListener(IPAddress.Loopback,0);socket.Start();var port=((IPEndPoint)socket.LocalEndpoint).Port;socket.Stop();return port; }
    static async Task<byte[]> Exchange(int port,IPAddress address,bool tcp,string name,CancellationToken token)
    {
        var query=Query(name);
        if(tcp)
        {
            using var client=new TcpClient(address.AddressFamily);await client.ConnectAsync(address,port,token);
            await TcpDnsFraming.WriteAsync(client.GetStream(),query,token);
            return (await TcpDnsFraming.ReadAsync(client.GetStream(),token))!;
        }
        using var udp=new UdpClient(address.AddressFamily);await udp.SendAsync(query,new IPEndPoint(address,port),token);
        return (await udp.ReceiveAsync(token)).Buffer;
    }
    public static async Task Run(Action<string,Action> test,Func<string,Func<Task>,Task> asyncTest,string directory)
    {
        test("Coverage does not equate healthy listeners with resolver steering",()=>
        {
            Check(DnsCoverage.Evaluate(true,true,true).State=="UNKNOWN","Healthy became full protection");
            Check(DnsCoverage.Evaluate(true,true,true,"HostsGuardian","Alternative").State=="PARTIAL","Alternative IPv6 path hidden");
            Check(DnsCoverage.Evaluate(true,false,true,"HostsGuardian").State=="PARTIAL","Missing IPv6 capability hidden");
            Check(DnsCoverage.Evaluate(true,true,true,"HostsGuardian","HostsGuardian","HostsGuardian").State=="UNKNOWN","Advertisements falsely proved device coverage");
            Check(DnsCoverage.Evaluate(true,false,false,"HostsGuardian","Unknown","HostsGuardian").State=="UNKNOWN","IPv4 intent falsely proved coverage");
            Check(DnsCoverage.Evaluate(true,true,null,"HostsGuardian").State=="UNKNOWN","Unknown IPv6 inferred");
        });
        test("Truthful WPF status expires coverage and separates IPv6 degradation",()=>
        {
            var now=DateTimeOffset.UtcNow;var model=new EngineStatusPresentation(()=>now);
            var status=new DnsServiceStatus {UdpListening=true,TcpListening=true,Ipv6UdpState="Faulted",Coverage=new(){State="PARTIAL"}};
            model.Complete(new(ConnectionState.Authenticated,"fixture"){Transport=status});
            Check(model.DnsService=="DEGRADED" && model.Coverage=="PARTIAL","IPv6 failure hidden");
            now=now.AddSeconds(31);Check(model.Coverage=="UNKNOWN","Expired coverage green");
        });
        await asyncTest("Dual-stack real UDP TCP shared allow block Safe Mode persistence and IPv6 telemetry",async()=>
        {
            Check(Socket.OSSupportsIPv6,"IPv6 required for this worker acceptance; rerun on capable worker");
            using var upstream=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var answer=Task.Run(async()=> {try {while(true) {var packet=await upstream.ReceiveAsync(deadline.Token);DnsProtocol.TryParseQuestion(packet.Buffer,out var question);var reply=DnsProtocol.BuildBlockedResponse(packet.Buffer,question,IPAddress.Parse("192.0.2.42"));await upstream.SendAsync(reply,packet.RemoteEndPoint,deadline.Token);}}catch(OperationCanceledException) {} });
            var settings=EngineSettings.FromConfig(new EngineConfig{DnsListenPort=Port(),UpstreamDnsIpv4="127.0.0.1",UpstreamDnsPort=((IPEndPoint)upstream.Client.LocalEndPoint!).Port,PolicyFilePath=Path.Combine(directory,"dual-policy.json")});
            for(var restart=0;restart<2;restart++)
            {
                var rules=new RuleStore("dual-"+restart);await using var udp=new DnsProxyServer(rules,settings);await using var tcp=new TcpDnsServer(settings,udp.RequestProcessor,udp.RuntimeStatus);
                var policy=new PolicyApplicationService(rules,new PolicyPersistence(settings.PolicyFilePath),udp.PolicyState);
                if(restart==0)Check(policy.Replace(["blocked.invalid"]).Success,"Fixture commit failed");else policy.InitializeForStartup();
                var before=File.ReadAllBytes(settings.PolicyFilePath);await udp.StartAsync();await tcp.StartAsync();
                foreach(var address in new[]{IPAddress.Loopback,IPAddress.IPv6Loopback})foreach(var transport in new[]{false,true})
                {
                    Check((await Exchange(settings.DnsPort,address,transport,"blocked.invalid",deadline.Token))[^4..].SequenceEqual(new byte[4]),"Block differs by family");
                    Check((await Exchange(settings.DnsPort,address,transport,"allowed.invalid",deadline.Token))[^4..].SequenceEqual(new byte[]{192,0,2,42}),"Allow differs by family");
                    Check(policy.SetSafeMode(true).Success,"Safe Mode failed");
                    Check((await Exchange(settings.DnsPort,address,transport,"blocked.invalid",deadline.Token))[^4..].SequenceEqual(new byte[]{192,0,2,42}),"Safe Mode differs by family");
                    Check(policy.SetSafeMode(false).Success,"Safe Mode exit failed");
                }
                var snapshot=udp.RuntimeStatus.GetSnapshot();Check(snapshot.Ipv6UdpState=="Listening" && snapshot.Ipv6TcpState=="Listening" && snapshot.UdpListening && snapshot.TcpListening,"Listener evidence missing");
                var rows=udp.Telemetry.Devices.Snapshot(FullDnsPolicy.Empty,"dual",1,DateTimeOffset.UtcNow).Devices;
                Check(rows.Any(r=>r.LastObservedAddress=="::1" && r.DeviceId==null) && rows.Any(r=>r.LastObservedAddress=="127.0.0.1"),"Mapped IPv4/IPv6 attribution wrong");
                Check(before.SequenceEqual(File.ReadAllBytes(settings.PolicyFilePath)),"Read-only diagnostics mutated persistence");
            }
            deadline.Cancel();await answer;
        });
        await asyncTest("IPv4-only configured compatibility retains both transports",async()=>
        {
            var settings=EngineSettings.FromConfig(new EngineConfig {DnsListenPort=Port(),EnableIpv6Dns=false});
            var rules=new RuleStore("ipv4-only");rules.SetBlockedDomains(["blocked.invalid"]);
            await using var udp=new DnsProxyServer(rules,settings);udp.PolicyState.Publish(new("Restored",true,1,1,false,"",""));
            await using var tcp=new TcpDnsServer(settings,udp.RequestProcessor,udp.RuntimeStatus);await udp.StartAsync();await tcp.StartAsync();
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            foreach(var transport in new[]{false,true})Check((await Exchange(settings.DnsPort,IPAddress.Loopback,transport,"blocked.invalid",deadline.Token))[7]==1,"IPv4-only unavailable");
            Check(udp.RuntimeStatus.GetSnapshot().Ipv6UdpState=="Disabled" && udp.RuntimeStatus.GetSnapshot().Ipv6TcpState=="Disabled","Disabled mislabeled failure");
        });
        await asyncTest("IPv6 TCP binding failure preserves IPv4 TCP capability",async()=>
        {
            using var occupied=new Socket(AddressFamily.InterNetworkV6,SocketType.Stream,ProtocolType.Tcp);occupied.DualMode=false;occupied.Bind(new IPEndPoint(IPAddress.IPv6Any,0));occupied.Listen(1);
            var settings=EngineSettings.FromConfig(new EngineConfig {DnsListenPort=((IPEndPoint)occupied.LocalEndPoint!).Port});
            await using var udp=new DnsProxyServer(new("tcp-fault"),settings);
            await using var tcp=new TcpDnsServer(settings,udp.RequestProcessor,udp.RuntimeStatus);await tcp.StartAsync();
            Check(udp.RuntimeStatus.GetSnapshot().TcpListening && udp.RuntimeStatus.GetSnapshot().Ipv6TcpState=="Faulted","TCP IPv6 fault hidden");
        });
        await asyncTest("IPv6 binding failure retains IPv4 and surfaces listener health fault",async()=>
        {
            using var occupied=new Socket(AddressFamily.InterNetworkV6,SocketType.Dgram,ProtocolType.Udp);occupied.DualMode=false;occupied.Bind(new IPEndPoint(IPAddress.IPv6Any,0));
            var port=((IPEndPoint)occupied.LocalEndPoint!).Port;var settings=EngineSettings.FromConfig(new EngineConfig{DnsListenPort=port});
            await using var udp=new DnsProxyServer(new("fault"),settings);await udp.StartAsync();
            var status=udp.RuntimeStatus.GetSnapshot();Check(status.UdpListening && status.Ipv6UdpState=="Faulted","IPv6 fault hidden");
            var health=new OperationalHealth("fault");health.Evaluate(status,udp.Telemetry.Counters(),new(0,null,null,null,0),DateTimeOffset.UtcNow);
            Check(health.Overall=="Critical","Healthy on failed IPv6 bind");
        });
    }
}
