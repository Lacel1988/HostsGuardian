using System.Collections.Immutable;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;
internal static class NetworkTopologyTests
{
    private sealed class FixtureTrust(bool race=false):IValidatorEndpointTrust
    {
        public EndpointFile Inspect(string path)=>new(0,1000,0xc1b0,2,0,1);
        public void Authenticate(System.Net.Sockets.Socket socket,EndpointFile before,string path)
        {if(race)throw new IOException("Fixture inode changed");}
    }
    private sealed class FixtureValidator(Func<EndpointValidationRequest,EndpointValidationResult?> respond):IEndpointValidator
    { public int Calls;public Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest request,CancellationToken cancellation){Calls++;return Task.FromResult(respond(request));} }
    private sealed class FailedHealthValidator:IEndpointValidator
    {
        public Task<bool> ProbeAsync(CancellationToken cancellation)=>Task.FromException<bool>(new IOException("Fixture unavailable"));
        public Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest request,CancellationToken cancellation)=>throw new Exception("Health-only mode must never request ARP");
    }
    public static async Task Run(Action<string,Action> test,Func<string,Func<Task>,Task> asyncTest)
    {
        void Check(bool yes,string reason){if(!yes)throw new Exception(reason);}
        test("Validator root endpoint metadata rejects fake owner permissions symlink and impostor credentials",()=>{
            var valid=new EndpointFile(0,1000,0xc1b0,2,0,1);
            LinuxValidatorEndpointTrust.ValidateMetadata(valid,true,1000);
            foreach(var bad in new[]{valid with{Owner=1000},valid with{Group=1001},valid with{Mode=0xc1b6},valid with{Mode=0xa1ff},valid with{Mode=0x81b0}})
            {try{LinuxValidatorEndpointTrust.ValidateMetadata(bad,true,1000);throw new Exception("Unsafe endpoint accepted");}catch(IOException){}}
            foreach(var mode in new ushort[]{0x41ff,0xa1ed,0x81ed})
            {try{LinuxValidatorEndpointTrust.ValidateMetadata(valid with{Mode=mode},false,1000);throw new Exception("Unsafe ancestor accepted");}catch(IOException){}}
            LinuxValidatorEndpointTrust.ValidateCreator(1,0,0);
            foreach(var peer in new[]{(123,1000u,1000u),(123,0u,0u),(1,0u,1000u)})
            {try{LinuxValidatorEndpointTrust.ValidateCreator(peer.Item1,peer.Item2,peer.Item3);throw new Exception("Fake endpoint accepted");}catch(IOException){}}
        });
        var now=DateTimeOffset.UtcNow;var id=Guid.NewGuid();const string mac="02:00:00:00:00:11";
        var registration=new DeviceRegistration(id,"Fixture TV",mac,"fixture","Explicit fixture registration");
        var policy=FullDnsPolicy.Empty with{Devices=[registration]};
        NetworkIdentityEvidence Evidence(string address="192.0.2.20",string candidateMac=mac)=>new(address,candidateMac,"","Kernel fixture",now.AddMinutes(-50)){Interface="fixture0",NeighborState="STALE",ReadAtUtc=now};
        var read=new BindingEvidenceRead(now,true,[Evidence()]);
        EndpointValidationResult Result(EndpointValidationRequest request)=>new(request.RequestId,request.Address,request.Interface,now,now,now,now,now.AddSeconds(45),"TargetedARP","Confirmed",[mac],"Fixture network claim");
        var store=new AddressBindingStore();var validator=new FixtureValidator(Result);
        var producer=new ActiveBindingProducer(store,()=>policy,()=>read,validator,()=>now);
        await asyncTest("Validator client rejects substituted endpoint and malformed greeting before any request; health probe sends no ARP",async()=>{
            foreach(var mode in new[]{"ready","bad-greeting","race"})
            {
                var path=Path.Combine(Path.GetTempPath(),"hg-ipc-"+Guid.NewGuid().ToString("N"));
                using var listener=new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.Unix,System.Net.Sockets.SocketType.Stream,System.Net.Sockets.ProtocolType.Unspecified);
                listener.Bind(new System.Net.Sockets.UnixDomainSocketEndPoint(path));listener.Listen(1);
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var server=Task.Run(async()=>{
                    using var peer=await listener.AcceptAsync(timeout.Token);using var stream=new System.Net.Sockets.NetworkStream(peer);
                    try{await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(mode=="bad-greeting"?"FAKE\n":"HG-NETWORKVALIDATOR/2 AUTHORIZED\n"),timeout.Token);}catch(IOException){}
                    var data=new byte[1];try{return await stream.ReadAsync(data,timeout.Token);}catch(IOException){return 0;}
                });
                try
                {
                    var client=new NetworkValidatorClient(path,new FixtureTrust(mode=="race"));
                    var ready=await client.ProbeAsync(timeout.Token);Check(ready==(mode=="ready"),"Endpoint/greeting trust wrong");
                    Check(await server==0,"Probe or failed trust sent a validation request");
                }
                finally{listener.Close();if(File.Exists(path))File.Delete(path);}
            }
        });
        await asyncTest("Validator health-only mode never issues ARP or clears passive bindings",async()=>{
            var healthOnly=new ActiveBindingProducer(store,()=>policy,()=>read,validator,()=>now,activeValidationEnabled:false);
            var before=store.Read();await healthOnly.RefreshAsync(default);
            Check(validator.Calls==0 && store.Read()==before,"Health probe changed bindings or sent ARP");
            Check(healthOnly.Health.State=="READY" && !healthOnly.Health.ActiveValidationEnabled,"Health mode missing");
            var passive=new AddressBindingStore();
            Check(passive.Replace(new(0,[new("192.0.2.20",null,id,"Fixture passive",now,now.AddSeconds(45),true){MacEvidence=mac}])),"Passive fixture setup failed");
            var prior=passive.Read();
            using var stop=new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
            var failed=new ActiveBindingProducer(passive,()=>policy,()=>read,new FailedHealthValidator(),()=>now,activeValidationEnabled:false);
            await failed.RunAsync(stop.Token);
            Check(passive.Read()==prior && passive.Read().Observations.Length==1 && failed.Health.State=="UNAVAILABLE","Health exception cleared passive state or hid unavailable status");
        });
        await asyncTest("Binding V2 exact active confirmation supports stale NUD and both DNS transports without permanent IP identity",async()=>{
            await producer.RefreshAsync(default);Check(store.Read().Observations.Single().ValidatedAtUtc==now,"No active binding");
            foreach(var transport in new[]{DnsTransport.Udp,DnsTransport.Tcp})Check(AddressBindingStore.Resolve(store.Read(),policy,new(transport,"192.0.2.20",0,now,null),now).DeviceId==id,"Transport identity mismatch");
            await producer.RefreshAsync(default);Check(validator.Calls==1,"Duplicate helper request");
            Check(AddressBindingStore.Resolve(store.Read(),policy,new(DnsTransport.Udp,"192.0.2.20",0,now,null),now.AddSeconds(45)).DeviceId==null,"Active evidence never expires");
        });
        await asyncTest("Binding V2 IP reuse conflict changed registry Forget and unavailable helper fail closed",async()=>{
            read=read with{Evidence=[Evidence(candidateMac:"02:00:00:00:00:12")]};await producer.RefreshAsync(default);Check(store.Read().Observations.Length==0,"IP reuse inherited identity");
            read=read with{Evidence=[Evidence(),Evidence(candidateMac:"02:00:00:00:00:12")]};await producer.RefreshAsync(default);Check(store.Read().Observations.Length==0,"Conflict accepted");
            read=read with{Evidence=[Evidence()]};var fresh=new ActiveBindingProducer(store,()=>policy,()=>read,new FixtureValidator(Result),()=>now);await fresh.RefreshAsync(default);
            var snapshot=store.Read();policy=policy with{Devices=[]};Check(AddressBindingStore.Resolve(snapshot,policy,new(DnsTransport.Udp,"192.0.2.20",0,now,null),now).DeviceId==null,"Forget not immediate");await fresh.RefreshAsync(default);Check(store.Read().Observations.Length==0,"Forgotten cache remained");
            policy=policy with{Devices=[registration with{Mac="02:00:00:00:00:12"}]};await fresh.RefreshAsync(default);Check(store.Read().Observations.Length==0,"Registration change retained binding");
            policy=policy with{Devices=[registration]};await new ActiveBindingProducer(store,()=>policy,()=>read,new FixtureValidator(_=>null),()=>now).RefreshAsync(default);Check(store.Read().Observations.Length==0,"Unavailable helper granted binding");
        });
        await asyncTest("Binding V2 rejects stale and ambiguous registry evidence changed during validation",async()=>{
            policy=policy with{Devices=[registration]};read=new(now,true,[Evidence()]);
            var race=new ActiveBindingProducer(store,()=>policy,()=>read,new FixtureValidator(request=>{policy=policy with{Devices=[registration,registration with{DeviceId=Guid.NewGuid()}]};return Result(request);}),()=>now);
            await race.RefreshAsync(default);Check(store.Read().Observations.Length==0,"In-flight ambiguous registration accepted");
            policy=policy with{Devices=[registration]};read=new(now,true,[Evidence()]);
            race=new ActiveBindingProducer(store,()=>policy,()=>read,new FixtureValidator(request=>{read=read with{ReadAtUtc=now.AddSeconds(-21)};return Result(request);}),()=>now);
            await race.RefreshAsync(default);Check(store.Read().Observations.Length==0,"In-flight stale observation accepted");
            read=new(now,true,[Evidence()]);
        });
        test("Binding V2 rejects wrong target method correlation time MAC spoof and expired helper result",()=>{
            var request=new EndpointValidationRequest(new string('a',32),"192.0.2.20","fixture0");var result=Result(request);
            foreach(var invalid in new[]{result with{Outcome="Conflict"},result with{Outcome="Timeout"},result with{Macs=[mac,"02:00:00:00:00:12"]},result with{Macs=["bad"]},result with{Address="192.0.2.21"},result with{Interface="other"},result with{Method="GenericRaw"},result with{RequestId="wrong"},result with{ObservedAtUtc=now.AddSeconds(1)},result with{ExpiresAtUtc=now},result with{ExpiresAtUtc=now.AddHours(1)}})
                Check(!ActiveBindingProducer.ValidResult(request,invalid,now),"Invalid helper evidence accepted");
        });
        test("Explicit future network aliases persist but never automatically link randomized MAC",()=>{
            var future=PolicyCanonicalization.Canonicalize(policy with{SchemaVersion=3,Program=PolicyProgram.Empty,Devices=[registration with{AcceptedNetworkIdentities=[new("02:00:00:00:00:12","fixture","Explicit user acceptance",now)]}]});
            var roundtrip=PolicyBackup.Import(PolicyBackup.Export(future));Check(roundtrip.Devices.Single().AcceptedNetworkIdentities?.Length==1,"Alias lost in backup");
            Check(RegisteredMacCorrelation.Find(future,["02:00:00:00:00:12"],1,true)==null,"Future alias silently activated without linking workflow");
            Check(ObservationNotificationKey.Create("02-00-00-00-00-11","192.0.2.20")==ObservationNotificationKey.Create(mac.ToLowerInvariant(),"192.0.2.21"),"Formatting duplicated observation notification");
        });
        test("Topology separates offline registry unknown access partial DNS and validated binding warning",()=>{
            var observation=new LanDeviceObservation(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",now,now,[Evidence()]){DnsActivity="OBSERVED",Coverage="PARTIAL"};
            var observed=DeviceIdentityProjection.Apply([observation],policy);var topology=TopologyProjection.Build(policy with{Devices=policy.Devices.Add(new(Guid.NewGuid(),"Offline fixture",null,"fixture","Explicit"))},observed,new(0,[]),now,gateways:["192.0.2.1"]);
            Check(topology.Nodes.Any(n=>n.Name=="Offline fixture" && n.Presence=="Not currently correlated"),"Offline device forgotten");
            var tv=topology.Nodes.Single(n=>n.DeviceId==id);Check(tv.Access=="Unknown" && tv.Coverage=="PARTIAL" && tv.Binding=="Unknown / unvalidated","False topology certainty");
            Check(topology.Links.Any(l=>l.Relationship=="DNS activity") && !topology.Links.Any(l=>l.Relationship is "Ethernet" or "Wi-Fi"),"Physical link fabricated");
            Check(topology.Nodes.Any(n=>n.Kind=="Gateway"),"Gateway missing");
            var evidence=new AccessTopologyEvidence(observation.ObservationDeviceId,"Wi-Fi","ap:fixture","network:fixture","Fixture network","PROVEN","AP fixture","Explicit association",now,now.AddSeconds(30));
            var enriched=TopologyProjection.Build(policy,observed,new(0,[]),now,access:[evidence]);Check(enriched.Nodes.Single(n=>n.DeviceId==id).Access=="Wi-Fi","Supported access not exposed");
            Check(TopologyProjection.Build(policy,observed,new(0,[]),now.AddMinutes(1),access:[evidence]).Nodes.Single(n=>n.DeviceId==id).Access=="Unknown","Expired access promoted");
            var conflict=TopologyProjection.Build(policy,observed,new(0,[]),now,access:[evidence,evidence with{Technology="Ethernet"}]).Nodes.Single(n=>n.DeviceId==id);
            Check(conflict.Access=="Unknown" && conflict.Evidence.Any(e=>e.Explanation.StartsWith("Conflicting access")),"Conflict evidence lost");
            var bounded=TopologyProjection.Build(policy with{Devices=Enumerable.Range(0,140).Select(i=>new DeviceRegistration(Guid.NewGuid(),"Fixture",null,"fixture","Explicit")).ToImmutableArray()},[],new(0,[]),now);
            Check(bounded.Nodes.Length==128 && bounded.OmittedNodes==13,"Topology inventory bound/count wrong");
        });
    }
}
