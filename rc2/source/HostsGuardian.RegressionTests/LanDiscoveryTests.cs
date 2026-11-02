using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;
internal static class LanDiscoveryTests
{
    static void Check(bool value,string message){if(!value)throw new Exception(message);}
    public static void Run(Action<string,Action> test)
    {
        var now=DateTimeOffset.UtcNow;
        NetworkIdentityEvidence E(string ip,string mac,string iface="fixture")=>new(ip,mac,"","OBSERVED: fixture kernel cache",now){Interface=iface,NeighborState="STALE"};
        test("Independent LAN device survives zero DNS with unknown coverage",()=>
        {
            var store=new LanObservationStore();var lan=store.Observe([E("192.0.2.238","02:00:00:00:00:01")],now);
            var row=LanObservationStore.Correlate(lan,[]).Single();
            Check(row.Presence=="OBSERVED" && row.DnsActivity=="NOT OBSERVED" && row.Coverage=="UNKNOWN" && row.ResolverPath=="UNKNOWN","LAN absence conflated with DNS absence");
        });
        test("IPv4 and IPv6 share provisional same-interface MAC observation epoch",()=>
        {
            var store=new LanObservationStore();var rows=store.Observe([E("192.0.2.9","02:00:00:00:00:01"),E("2001:db8::9","02:00:00:00:00:01")],now);
            var id=rows.Single().ObservationDeviceId;
            Check(rows[0].Evidence.Length==2 && store.Observe([E("192.0.2.10","02:00:00:00:00:01")],now)[0].ObservationDeviceId==id,"Binding change broke session correlation");
            Check(rows[0].Stability=="SESSION / PROVISIONAL","MAC became permanent identity");
        });
        test("Interface scope and conflicting address evidence are preserved",()=>
        {
            var rows=new LanObservationStore().Observe([E("192.0.2.9","02:00:00:00:00:01"),E("192.0.2.9","02:00:00:00:00:02"),E("2001:db8::1","02:00:00:00:00:01","other")],now);
            Check(rows.Length==3,"Cross-interface identity inferred or conflict discarded");
            var store=new DeviceDnsDiagnosticsStore();store.Record(new(DnsTransport.Udp,"192.0.2.9",1,now,null),null,"Unknown","Received",now);
            var dns=store.Snapshot(FullDnsPolicy.Empty,"fixture",0,now).Devices;
            Check(LanObservationStore.Correlate(rows,dns).All(r=>r.DnsActivity=="NOT OBSERVED"),"Ambiguous source incorrectly attributed");
        });
        test("Observed DNS use is partial evidence never complete coverage",()=>
        {
            var rows=new LanObservationStore().Observe([E("2001:db8::9","02:00:00:00:00:01")],now);
            var store=new DeviceDnsDiagnosticsStore();store.Record(new(DnsTransport.Udp,"2001:db8::9",1,now,null),null,"Unknown","Received",now);
            var row=LanObservationStore.Correlate(rows,store.Snapshot(FullDnsPolicy.Empty,"fixture",0,now).Devices).Single();
            Check(row.Coverage=="PARTIAL" && row.DnsActivity=="OBSERVED" && row.ResolverPath=="UNKNOWN","Observed use falsely proved exclusivity");
        });
        test("Kernel ARP NDP parsing rejects incomplete observations and identifies private MAC possibility",()=>
        {
            var rows=PassiveIdentityEvidence.ParseNeighbours("""[{"dst":"2001:db8::5","dev":"fixture","lladdr":"02:00:00:00:00:01","state":["STALE"]},{"dst":"192.0.2.5","dev":"fixture","lladdr":"00:00:00:00:00:00","state":["FAILED"]}]""",now);
            Check(rows.Length==1 && rows[0].PrivateMacPossible && rows[0].Hostname=="","NDP ignored or identity fabricated");
            Check(PassiveIdentityEvidence.ParseNeighbours(new string('x',65537),now).Length==0,"Unbounded provider input");
        });
        test("Independent observation retention and capacity bounded without raw DNS history",()=>
        {
            var store=new LanObservationStore();var rows=store.Observe(Enumerable.Range(1,80).Select(i=>E("192.0.2."+i,$"02:00:00:00:00:{i:X2}")),now);
            Check(rows.Length==64 && rows.All(r=>r.Evidence.Length<=8),"Observation retention unbounded");
            Check(store.Observe([],now.AddMinutes(11)).Length==0,"Stale presence retained as current");
        });
        test("Discovery targets derive local subnet without assumed router or truncated large subnet",()=>
        {
            var targets=LanDiscoveryRefresh.Targets(System.Net.IPAddress.Parse("198.51.100.250"),24);
            Check(targets.Length==253 && targets.Contains("198.51.100.238") && !targets.Contains("198.51.100.250") && !targets.Contains("198.51.100.255"),"Host range or self/broadcast handling wrong");
            Check(LanDiscoveryRefresh.Targets(System.Net.IPAddress.Parse("198.51.100.2"),16).Length==0,"Large subnet silently partially scanned");
        });
        test("Owner-only Monitor payload remains bounded and explicitly reports omitted LAN evidence",()=>
        {
            var dns=new DeviceDnsDiagnosticsStore();
            foreach(var i in Enumerable.Range(1,64))dns.Record(new(DnsTransport.Udp,"192.0.2."+i,1,now,null),null,"Unknown","Received",now);
            var snapshot=dns.Snapshot(FullDnsPolicy.Empty,"fixture",0,now);
            var lan=Enumerable.Range(1,64).Select(i=>new LanDeviceObservation(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",now,now,
                Enumerable.Range(1,8).Select(j=>new NetworkIdentityEvidence($"2001:db8:{i:x}::{j:x}","02:00:00:00:00:01",new string('h',128),new string('p',160),now){Interface=new string('i',64),NeighborState="STALE"}).ToArray())).ToArray();
            var engine=new DnsProxyServer(new RuleStore("bounded-discovery-fixture"),new EngineConfig());
            var local=new LocalMonitorSnapshot(1,now,1,now,engine.RuntimeStatus.GetSnapshot(),[])
                {Diagnostics=engine.RuntimeStatus.Diagnostics!.Snapshot() with {Devices=snapshot with {LanDevices=lan}}};
            var bytes=LocalMonitorStatusPublisher.SerializeBounded(local);
            using var document=System.Text.Json.JsonDocument.Parse(bytes);var result=document.RootElement.GetProperty("diagnostics").GetProperty("devices");
            Check(bytes.Length<=131072 && result.GetProperty("devices").GetArrayLength()==64 && result.GetProperty("lanDevices").EnumerateArray().Any(d=>d.GetProperty("evidenceOmitted").GetInt32()>0),"Snapshot grew or silently discarded bounded evidence");
        });
    }
}
