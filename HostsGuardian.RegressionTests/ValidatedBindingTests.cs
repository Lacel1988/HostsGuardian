using System.Net;
using System.Net.Sockets;
using System.Text;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;
internal static class ValidatedBindingTests
{
    public static async Task Run(Action<string,Action> test,Func<string,Func<Task>,Task> asyncTest,string folder)
    {
        void Check(bool yes,string reason) {if(!yes)throw new Exception(reason);}
        var now=DateTimeOffset.UtcNow;var id=Guid.NewGuid();const string mac="02:AB:CD:01:02:03";
        var registration=new DeviceRegistration(id,"Fixture appliance",mac,"fixture","Explicit test registration");
        var policy=FullDnsPolicy.Empty with {Devices=[registration],Overrides=[new(id,"binding.invalid",DeviceDomainRuleState.Block)]};
        NetworkIdentityEvidence E(string address,string? m=null,string state="REACHABLE") => new(address,m ?? mac,"","OBSERVED: kernel neighbour",now)
            {Interface="fixture0",NeighborState=state,ConfirmedAtUtc=now,ReadAtUtc=now};
        BindingEvidenceRead evidence=new(now,true,[E("192.0.2.31")]);
        var store=new AddressBindingStore();var producer=new ValidatedBindingProducer(store,()=>policy,()=>evidence,()=>now);
        DnsRequestContext Context(string address,DnsTransport transport=DnsTransport.Udp)=>new(transport,address,0,now,null);
        Guid? Resolve(string address)=>AddressBindingStore.Resolve(store.Read(),policy,Context(address),now).DeviceId;
        test("Binding producer fresh registered MAC authorizes IPv4 and publishes provenance without policy mutation",()=>{
            producer.Refresh();Check(Resolve("192.0.2.31")==id && store.Read().Generation==1,"Missing valid binding");
            var b=store.Read().Observations.Single();Check(b.MacEvidence==mac && b.Interface=="fixture0" && b.ExpiresAtUtc==now.AddSeconds(15),"Evidence missing");
            producer.Refresh();Check(store.Read().Generation==1,"Unchanged evidence changed generation");
        });
        test("Binding producer DHCP move invalidates old IP and binds new IP",()=>{
            evidence=new(now,true,[E("192.0.2.32")]);producer.Refresh();Check(Resolve("192.0.2.31")==null && Resolve("192.0.2.32")==id,"DHCP identity leak");
        });
        test("Binding producer IP reuse different MAC never inherits registered identity",()=>{
            evidence=new(now,true,[E("192.0.2.32","02:AB:CD:04:05:06")]);producer.Refresh();Check(Resolve("192.0.2.32")==null,"IP reuse leak");
        });
        test("Binding producer stale neighbour and age expiry fail closed",()=>{
            evidence=new(now,true,[E("192.0.2.31","", "STALE") with{Mac=mac}]);producer.Refresh();Check(Resolve("192.0.2.31")==null,"STALE authorized");
            evidence=new(now,true,[E("192.0.2.31")]);producer.Refresh();var snapshot=store.Read();
            Check(AddressBindingStore.Resolve(snapshot,policy,Context("192.0.2.31"),now.AddSeconds(15)).DeviceId==null,"Expired snapshot authorized");
            evidence=evidence with {ReadAtUtc=now.AddSeconds(-16)};producer.Refresh();Check(store.Read().Observations.Length==0,"Stale provider retained binding");
        });
        test("Binding producer conflicting MAC IP interface duplicate registry and incomplete evidence reject identity",()=>{
            foreach(var rows in new[]{new[]{E("192.0.2.31"),E("192.0.2.31","02:AB:CD:04:05:06")},
                new[]{E("192.0.2.31"),E("192.0.2.31") with{Interface="fixture1"}}}) {
                evidence=new(now,true,rows);producer.Refresh();Check(store.Read().Observations.Length==0,"Conflict authorized"); }
            evidence=new(now,true,[E("192.0.2.31")]);policy=policy with {Devices=[registration,registration with{DeviceId=Guid.NewGuid()}]};
            producer.Refresh();Check(store.Read().Observations.Length==0,"Duplicate registry authorized");policy=policy with{Devices=[registration]};
            evidence=evidence with{Complete=false};producer.Refresh();Check(store.Read().Observations.Length==0,"Partial input authorized");
            evidence=new(now,true,[E("192.0.2.31")]);producer.Refresh();evidence=new(now,true,[]);producer.Refresh();Check(Resolve("192.0.2.31")==null,"Disappearance retained binding");
        });
        test("Binding producer forgotten registration and changed registered MAC invalidate existing snapshot immediately",()=>{
            evidence=new(now,true,[E("192.0.2.31")]);producer.Refresh();var snapshot=store.Read();
            Check(AddressBindingStore.Resolve(snapshot,policy with{Devices=[]},Context("192.0.2.31"),now).DeviceId==null,"Forget leaked policy");
            Check(AddressBindingStore.Resolve(snapshot,policy with{Devices=[registration with{Mac="02:AB:CD:04:05:06"}]},Context("192.0.2.31"),now).DeviceId==null,"MAC update leaked policy");
        });
        test("Binding producer randomized MAC mismatch and IPv6 remain unbound while diagnostic identity is preserved",()=>{
            evidence=new(now,true,[E("192.0.2.31","02:AB:CD:04:05:06"),E("2001:db8::31")]);producer.Refresh();Check(store.Read().Observations.Length==0,"Weak identity/IPv6 accepted");
            var observation=new LanDeviceObservation(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",now,now,[E("192.0.2.31")]);
            Check(DeviceIdentityProjection.Apply([observation],policy).Single().Identity!.DeviceId==id,"Diagnostic projection regressed");
        });
        test("Binding kernel parser rejects truncation malformed data and unavailable trust without promoting cached states",()=>{
            Check(!PassiveIdentityEvidence.ParseBindingNeighbours("not JSON",now).Complete,"Malformed trusted");
            Check(!PassiveIdentityEvidence.ParseBindingNeighbours("[{}]",now).Complete,"Incomplete trusted");
            var item="{\"dst\":\"192.0.2.31\",\"dev\":\"fixture0\",\"lladdr\":\"02:ab:cd:01:02:03\",\"state\":[\"STALE\"]}";
            var parsed=PassiveIdentityEvidence.ParseBindingNeighbours("["+item+"]",now);Check(parsed.Complete && ValidatedBindingProducer.Build(policy,parsed,now).Length==0,"Cached promoted");
            Check(!PassiveIdentityEvidence.ParseBindingNeighbours("["+string.Join(',',Enumerable.Repeat(item,64))+"]",now).Complete,"Truncation trusted");
        });
        test("Binding parser retains negative neighbour evidence to prevent cross-interface IP ambiguity",()=>{
            const string json="[{\"dst\":\"192.0.2.31\",\"dev\":\"fixture0\",\"lladdr\":\"02:ab:cd:01:02:03\",\"state\":[\"REACHABLE\"]},{\"dst\":\"192.0.2.31\",\"dev\":\"fixture1\",\"state\":[\"INCOMPLETE\"]}]";
            var parsed=PassiveIdentityEvidence.ParseBindingNeighbours(json,now);
            Check(parsed.Complete && parsed.Evidence.Length==2 && ValidatedBindingProducer.Build(policy,parsed,now).Length==0,"Negative interface conflict discarded");
        });
        test("Kernel freshness separates cached rereads from confirmation and rejects invalid ages",()=>{
            foreach(var state in new[]{"REACHABLE","STALE","DELAY","PROBE","FAILED"}) {
                var json="[{\"dst\":\"192.0.2.31\",\"dev\":\"fixture0\",\"lladdr\":\"02:ab:cd:01:02:03\",\"state\":[\""+state+"\"],\"confirmed\":120,\"updated\":100}]";
                var parsed=PassiveIdentityEvidence.ParseBindingNeighbours(json,now);var row=parsed.Evidence.Single();
                Check(row.ReadAtUtc==now && row.ConfirmedAtUtc==now.AddSeconds(-120) && row.ObservedAtUtc==now.AddSeconds(-100),"Read promoted confirmation");
                Check(ValidatedBindingProducer.Build(policy,parsed,now).Length==0,"Old confirmation authorized");
                var reread=PassiveIdentityEvidence.ParseBindingNeighbours(json.Replace("120","130").Replace("100","110"),now.AddSeconds(10)).Evidence.Single();
                Check(reread.ConfirmedAtUtc==row.ConfirmedAtUtc && reread.ObservedAtUtc==row.ObservedAtUtc,"Cached reread renewed evidence");
            }
            var missing=new BindingEvidenceRead(now,true,[E("192.0.2.31") with{ConfirmedAtUtc=null}]);
            Check(ValidatedBindingProducer.Build(policy,missing,now).Length==0,"Missing confirmation authorized");
        });
        test("Cached presence retention uses read time without renewing underlying observation",()=>{
            var stale=E("192.0.2.31",state:"STALE") with {ObservedAtUtc=now.AddMinutes(-49),ReadAtUtc=now,ConfirmedAtUtc=now.AddMinutes(-50)};
            var observations=new LanObservationStore();var first=observations.Observe([stale],now).Single();
            var second=observations.Observe([stale with{ReadAtUtc=now.AddSeconds(16)}],now.AddSeconds(16)).Single();
            Check(first.ObservationDeviceId==second.ObservationDeviceId && second.LastObservedUtc==stale.ObservedAtUtc && second.LastReadAtUtc==now.AddSeconds(16),"Read revived observation or changed epoch");
            Check(observations.Observe([],now.AddMinutes(11)).Length==0,"Cached evidence retained indefinitely without reads");
            foreach(var age in new[]{"-1","\"invalid\"","315360001"}) {
                var json="[{\"dst\":\"192.0.2.31\",\"dev\":\"fixture0\",\"lladdr\":\"02:ab:cd:01:02:03\",\"state\":[\"REACHABLE\"],\"confirmed\":"+age+"}]";
                var read=PassiveIdentityEvidence.ParseBindingNeighbours(json,now);
                Check(ValidatedBindingProducer.Build(policy,read,now).Length==0,"Malformed age authorized");
            }
        });
        await asyncTest("Binding producer unavailable provider invalidates snapshot and cancellation clears observations",async()=>{
            evidence=new(now,true,[E("192.0.2.31")]);var unavailable=false;
            var background=new ValidatedBindingProducer(store,()=>policy,()=>unavailable?throw new IOException("fixture unavailable"):evidence,()=>now);
            background.Refresh();Check(Resolve("192.0.2.31")==id,"Fixture missing");unavailable=true;background.Refresh();Check(store.Read().Observations.Length==0,"Unavailable evidence retained binding");
            unavailable=false;using var token=new CancellationTokenSource();var run=background.RunAsync(token.Token);Check(Resolve("192.0.2.31")==id,"Background did not produce binding");
            token.Cancel();await run;Check(store.Read().Observations.Length==0,"Cancelled producer retained binding");
        });
        await asyncTest("Binding shared UDP TCP processor enforces bound device only and preserves global fallback revision",async()=>{
            using var upstream=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var settings=EngineSettings.FromConfig(new EngineConfig{UpstreamDnsIpv4="127.0.0.1",UpstreamDnsPort=((IPEndPoint)upstream.Client.LocalEndPoint!).Port});
            var rules=new RuleStore("binding-fixture");var application=new PolicyApplicationService(rules,new PolicyPersistence(Path.Combine(folder,"binding-policy.json")));
            Check(application.ReplaceFull(new(0,policy)).Success,"Fixture commit failed");var state=application.State.GetSnapshot();
            var processor=new DnsRequestProcessor(rules,settings,new UpstreamDnsForwarder(settings),application.State);
            new ValidatedBindingProducer(processor.Bindings,()=>policy,()=>new(now,true,[E("192.0.2.31")]),()=>now).Refresh();
            var query=new List<byte>{0x12,0x34,1,0,0,1,0,0,0,0,0,0};foreach(var label in "binding.invalid".Split('.')) {query.Add((byte)label.Length);query.AddRange(Encoding.ASCII.GetBytes(label));}query.AddRange(new byte[]{0,0,1,0,1});
            foreach(var transport in new[]{DnsTransport.Udp,DnsTransport.Tcp}) {
                var response=await processor.ProcessAsync(query.ToArray(),Context("192.0.2.31",transport),timeout.Token);
                Check(response!=null && processor.Observations.Read().Last() is{DeviceId:var found,Blocked:true} && found==id,"Bound transport not blocked"); }
            var answer=Task.Run(async()=>{var request=await upstream.ReceiveAsync(timeout.Token);var bytes=request.Buffer;bytes[2]=0x81;bytes[3]=0x80;await upstream.SendAsync(bytes,request.RemoteEndPoint,timeout.Token);});
            await processor.ProcessAsync(query.ToArray(),Context("192.0.2.32"),timeout.Token);await answer;
            var decision=processor.Observations.Read().Last();Check(!decision.Blocked && decision.DeviceId==null && decision.Reason=="GlobalAllow","Unbound inherited device rule");
            Check(application.State.GetSnapshot()==state && processor.Telemetry.Counters().PolicyBlocked==2,"Binding mutated policy or telemetry incorrect");
        });
    }
}
