using HostsGuardian.Core.Models;
using HostsGuardian.DnsEngine;
using System.Collections.Immutable;
using System.Text.Json;

internal static class DeviceDiagnosticsTests
{
    private static void Check(bool value,string message) { if(!value) throw new Exception(message); }
    public static void Run(Action<string,Action> test,string directory)
    {
        test("LAN-only user metadata projects without DNS or execution binding and preserves hostname",()=>
        {
            var now=DateTimeOffset.UtcNow;var id=Guid.NewGuid();var mac="02:00:00:00:00:01";
            var observation=new LanDeviceObservation(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",now,now,
                [new("2001:db8::1",mac,"Observed-host","OBSERVED: fixture",now){Interface="fixture",PrivateMacPossible=true}]);
            var policy=new FullDnsPolicy(3,[],[new(id,"Registered name",mac,"fixture","Explicit user registration"){Metadata=new("Friendly alias","","Phone","")}],[])
                {Program=new([new(Guid.NewGuid(),"Family",[id],[])],[],[],[])};
            var result=HostsGuardian.Core.Services.DeviceIdentityProjection.Apply([observation],policy).Single();
            Check(result.Identity is {FriendlyName:"Friendly alias",ObservedHostname:"Observed-host",Confidence:"USER-CONFIRMED",PrivateMacPossible:true} && result.Identity.DeviceId==id && result.Identity.Groups.SequenceEqual(new[]{"Family"}),"User metadata lost or replaced observed hostname");
            Check(result.ObservationDeviceId==observation.ObservationDeviceId && result.DnsActivity=="NOT OBSERVED" && result.Coverage=="UNKNOWN" && result.ResolverPath=="UNKNOWN","Identity invented DNS coverage");
            var renamed=HostsGuardian.Core.Services.DeviceIdentityProjection.Rename(policy.Devices[0],"Updated alias");
            Check(renamed.Name=="Updated alias" && renamed.Metadata?.Alias=="Updated alias" && renamed.DeviceId==id,"Stale alias masks a WPF name edit");
        });
        test("Identity projection refuses IP-only duplicate registrations and cross-interface MAC ambiguity",()=>
        {
            var now=DateTimeOffset.UtcNow;var mac="02:00:00:00:00:01";
            var observation=new LanDeviceObservation(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",now,now,[new("192.0.2.1",mac,"","OBSERVED: fixture",now){Interface="a"}]);
            var policy=new FullDnsPolicy(2,[],[new(Guid.NewGuid(),"First",mac,"fixture","explicit")],[]);
            var withoutMac=observation with {Evidence=[observation.Evidence[0] with {Mac=""}]};
            Check(HostsGuardian.Core.Services.DeviceIdentityProjection.Apply([withoutMac],policy)[0].Identity!.DeviceId==null,"IP-only association accepted");
            var duplicate=policy with {Devices=policy.Devices.Add(new(Guid.NewGuid(),"Second",mac,"fixture","explicit"))};
            Check(HostsGuardian.Core.Services.DeviceIdentityProjection.Apply([observation],duplicate)[0].Identity!.State=="Ambiguous","Duplicate registration silently merged");
            var other=observation with {ObservationDeviceId=Guid.NewGuid(),Evidence=[observation.Evidence[0] with {Interface="b"}]};
            Check(HostsGuardian.Core.Services.DeviceIdentityProjection.Apply([observation,other],policy).All(o=>o.Identity!.DeviceId==null),"Cross-interface ambiguity silently merged");
            Check(HostsGuardian.Core.Services.DeviceIdentityProjection.Apply([observation with {EvidenceOmitted=1}],policy)[0].Identity!.DeviceId==null,"Incomplete evidence associated identity");
        });
        test("Passive identity evidence is bounded address metadata and includes actual local adapters",()=>
        {
            var rows=HostsGuardian.Core.Services.PassiveIdentityEvidence.Read();
            Check(rows.Length<=64 && rows.All(r=>System.Net.IPAddress.TryParse(r.Address,out _) && r.Hostname.Length<=128 && r.Provenance.StartsWith("OBSERVED:")),"Invalid passive evidence");
            Check(rows.Where(r=>r.Hostname!="").All(r=>r.Hostname==Environment.MachineName),"Fabricated hostname");
        });
        test("Device diagnostics stable DeviceId aggregation and confirmed alias follow Engine policy",()=>
        {
            var store=new DeviceDnsDiagnosticsStore(); var device=Guid.NewGuid(); var now=DateTimeOffset.UtcNow;
            var first=store.Record(new(DnsTransport.Udp,"192.0.2.1",1,now,null),device,"Validated","Received",now);
            store.Outcome(first,"Allowed",now);
            var second=store.Record(new(DnsTransport.Tcp,"192.0.2.2",1,now,null),device,"Validated","Received",now);
            store.Outcome(second,"Blocked",now);
            var policy=new FullDnsPolicy(3,[],[new(device,"Registered fixture",null,"fixture","explicit")],[]);
            var row=store.Snapshot(policy,"fixture",1,now).Devices.Single();
            Check(row.DeviceId==device && row.Window.Received==2 && row.Window.Allowed==1 && row.Window.PolicyBlocked==1 && row.LastObservedAddress=="192.0.2.2","IP change broke actual DeviceId attribution");
            policy=policy with {Devices=[policy.Devices[0] with {Metadata=new("Confirmed fixture alias","","Laptop","")}]};
            row=store.Snapshot(policy,"fixture",2,now).Devices.Single();
            Check(row.Name=="Confirmed fixture alias" && row.NameEvidence=="USER-CONFIRMED" && row.Window.Received==2,"Monitor identity did not follow the Engine registry");
        });
        test("Unknown source grouping never fabricates a stable device identity",()=>
        {
            var store=new DeviceDnsDiagnosticsStore(); var now=DateTimeOffset.UtcNow;
            foreach(var address in new[]{"192.0.2.1","192.0.2.2"}) store.Record(new(DnsTransport.Udp,address,1,now,null),null,"Unknown","Received",now);
            var rows=store.Snapshot(FullDnsPolicy.Empty,"fixture",0,now).Devices;
            Check(rows.Length==2 && rows.All(r=>r.DeviceId==null && r.NameEvidence=="UNKNOWN" && r.Name=="Unknown device"),"Unknown addresses became physical identities");
        });
        test("Device DNS diagnostics record failures drops and connection rejection separately",()=>
        {
            var store=new DeviceDnsDiagnosticsStore(); var now=DateTimeOffset.UtcNow; var context=new DnsRequestContext(DnsTransport.Udp,"192.0.2.1",1,now,null);
            var key=store.Record(context,null,"Unknown","Received",now); store.Outcome(key,"Servfail",now);
            key=store.Record(context,null,"Unknown","Received",now);store.Outcome(key,"Dropped",now);
            store.Record(context,null,"Unknown","ConnectionRejected",now);
            var row=store.Snapshot(FullDnsPolicy.Empty,"fixture",0,now).Devices.Single();
            Check(row.Window.Received==2 && row.Window.Failed==1 && row.Window.Servfail==1 && row.Window.Rejected==1 && row.Window.CapacityDropped==1 && row.Window.TcpConnectionsRejected==1,"Exclusive outcome or connection/query semantics wrong");
        });
        test("Device DNS diagnostics bounded eviction rejects late outcomes for replaced epochs",()=>
        {
            var store=new DeviceDnsDiagnosticsStore();var now=DateTimeOffset.UtcNow;
            var original=store.Record(new(DnsTransport.Udp,"192.0.2.1",1,now,null),null,"Unknown","Received",now);
            for(var i=2;i<=65;i++)store.Record(new(DnsTransport.Udp,"192.0.2."+i,1,now,null),null,"Unknown","Received",now.AddMilliseconds(i));
            store.Record(new(DnsTransport.Udp,"192.0.2.1",1,now,null),null,"Unknown","Received",now.AddSeconds(1));
            store.Outcome(original,"Allowed",now.AddSeconds(2));
            var snapshot=store.Snapshot(FullDnsPolicy.Empty,"fixture",0,now.AddSeconds(2));
            Check(snapshot.Devices.Length==64 && snapshot.EvictedSources==2 && snapshot.Devices.Sum(r=>r.Window.Allowed)==0,"Evicted identity epoch received another source's outcome");
            Check(store.Snapshot(FullDnsPolicy.Empty,"fixture",0,now.AddSeconds(603)).Devices.Length==0,"Expired device aggregates retained");
        });
        test("Local device publication remains bounded owner-only without raw domains or credentials",()=>
        {
            var engine=new DnsProxyServer(new RuleStore("device-publisher-fixture"),new EngineConfig());var now=DateTimeOffset.UtcNow;
            engine.RequestProcessor.ObserveCapacityDrop(new(DnsTransport.Udp,"192.0.2.1",1,now,null));
            var path=Path.Combine(directory,"device-monitor.json");new LocalMonitorStatusPublisher(engine.RuntimeStatus,path).PublishOnce();
            var json=File.ReadAllText(path);using var document=JsonDocument.Parse(json);
            Check(document.RootElement.GetProperty("diagnostics").GetProperty("devices").GetProperty("devices").GetArrayLength()==1 && new FileInfo(path).Length<131072 && !json.Contains("fixture.invalid") && !json.Contains("credential",StringComparison.OrdinalIgnoreCase),"Publisher leaked query/security state or omitted device evidence");
            if(!OperatingSystem.IsWindows())Check(File.GetUnixFileMode(path)==(UnixFileMode.UserRead|UnixFileMode.UserWrite),"Device context readable outside Engine owner");
        });
    }
}
