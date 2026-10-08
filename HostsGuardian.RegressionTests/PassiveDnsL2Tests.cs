using System.Net;
using System.Net.Sockets;
using System.Text;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class PassiveDnsL2Tests
{
    private sealed class FixtureTrust:IValidatorEndpointTrust
    {
        public int Inspections,Authentications;
        public EndpointFile Inspect(string path){Inspections++;return new(0,0,0xC1B0,1,0,0);}
        public void Authenticate(Socket socket,EndpointFile before,string path){Authentications++;}
    }
    private sealed class Validator(Func<string,Task<PassiveDnsL2Read?>> read):IEndpointValidator
    {
        public int ActiveRequests;
        public Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest request,CancellationToken cancellation)
        {ActiveRequests++;throw new Exception("Passive mode attempted ARP");}
        public Task<PassiveDnsL2Read?> ReadPassiveDnsAsync(string id,CancellationToken cancellation)=>read(id);
    }
    public static async Task Run(Action<string,Action> test,Func<string,Func<Task>,Task> asyncTest,string folder)
    {
        void Check(bool value,string message){if(!value)throw new Exception(message);}
        var now=DateTimeOffset.UtcNow;
        const string mac="02:AB:CD:01:02:03",otherMac="02:AB:CD:04:05:06",address="192.0.2.31";
        var id=Guid.NewGuid();var other=Guid.NewGuid();
        var registration=new DeviceRegistration(id,"Fixture TV",mac,"fixture","Explicit test registration");
        var policy=FullDnsPolicy.Empty with{Devices=[registration,new(other,"Other",otherMac,"fixture","Explicit")],Overrides=[new(id,"youtube.com",DeviceDomainRuleState.Block)]};
        var kernelConfirmation=now.AddMinutes(-5);
        NetworkIdentityEvidence E(string a=address,string m=mac)=>new(a,m,"","OBSERVED: kernel neighbour",kernelConfirmation)
            {Interface="fixture0",NeighborState="STALE",ConfirmedAtUtc=kernelConfirmation,ReadAtUtc=now};
        BindingEvidenceRead Neighbours(params NetworkIdentityEvidence[] rows)=>new(now,true,rows.Length==0?[E()]:rows);
        PassiveDnsL2Claim Claim(string a=address,string m=mac)=>new(a,m,"fixture0",now,now.AddSeconds(10));
        PassiveDnsL2Read Read(string requestId="fixture",params PassiveDnsL2Claim[] claims)=>new(requestId,"PassiveDnsL2",true,now,"Fixture L2 only",claims.Length==0?[Claim()]:claims);
        test("Passive DNS L2 supports fresh received frame despite old STALE neighbour without renewing confirmation",()=>{
            var neighbours=Neighbours();Check(ValidatedBindingProducer.Build(policy,neighbours,now).Length==0,"STALE independently trusted");
            var rows=PassiveDnsL2BindingProducer.Build(policy,neighbours,Read(),"fixture",now);
            Check(rows.Single().DeviceId==id && rows.Single().ValidationMethod=="PassiveDnsL2" && rows.Single().ExpiresAtUtc==now.AddSeconds(10),"L2 evidence missing");
            Check(neighbours.Evidence.Single().ConfirmedAtUtc==now.AddMinutes(-5),"Neighbour confirmation altered");
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(E(),E("2001:db8::31")),Read(),"fixture",now).Single().DeviceId==id,"Same-interface IPv6 neighbour erased valid IPv4 evidence");
        });
        test("Passive DNS L2 expiry malformed timestamps readback and configuration fail closed",()=>{
            var read=Read();
            foreach(var bad in new[]{read with{Complete=false},read with{RequestId="wrong"},read with{Method="TargetedARP"},
                read with{ReadAtUtc=now.AddSeconds(1)},read with{ReadAtUtc=now.AddSeconds(-3)},read with{Evidence=null!},
                read with{Evidence=[Claim() with{ObservedAtUtc=now.AddSeconds(1)}]},read with{Evidence=[Claim() with{ExpiresAtUtc=now.AddSeconds(11)}]},
                read with{Evidence=[Claim() with{ExpiresAtUtc=now}]}})
                Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(),bad,"fixture",now).Length==0,"Invalid IPC claim trusted");
            var advanced=now.AddSeconds(10);
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours() with{ReadAtUtc=advanced},read with{ReadAtUtc=advanced},"fixture",advanced).Length==0,"Readback renewed frame");
            foreach(var limit in new[]{TimeSpan.Zero,TimeSpan.FromSeconds(16)})
                Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(),read,"fixture",now,limit).Length==0,"Invalid freshness accepted");
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(),read,"fixture",now,TimeSpan.FromSeconds(1)).Single().ExpiresAtUtc==now.AddSeconds(1),"Tighter limit ignored");
        });
        test("Passive DNS L2 IP MAC interface conflicts and incomplete neighbours cannot authorize identity",()=>{
            foreach(var claims in new[]{new[]{Claim(),Claim(m:otherMac)},new[]{Claim(),Claim(a:"192.0.2.32")},
                new[]{Claim(),Claim() with{Interface="fixture1"}}})
                Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(),Read("fixture",claims),"fixture",now).Length==0,"Conflicting L2 claims merged");
            foreach(var evidence in new[]{Neighbours(E(m:otherMac)),Neighbours(E(),E() with{Interface="fixture1"}),
                Neighbours(E(),E(a:"192.0.2.32")),Neighbours() with{Complete=false},Neighbours(E() with{NeighborState="FAILED"}),
                Neighbours() with{ReadAtUtc=now.AddSeconds(-3)},new BindingEvidenceRead(now,true,[])})
                Check(PassiveDnsL2BindingProducer.Build(policy,evidence,Read(),"fixture",now).Length==0,"Kernel conflict/absence ignored");
        });
        test("Passive DNS L2 IP reuse randomized MAC forgotten registry ambiguous registration IPv6 fail closed",()=>{
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(E(m:otherMac)),Read("fixture",Claim(m:otherMac)),"fixture",now).Single().DeviceId==other,"IP reuse retained TV identity");
            foreach(var current in new[]{policy with{Devices=[]},policy with{Devices=[registration,registration with{DeviceId=Guid.NewGuid()}]}})
                Check(PassiveDnsL2BindingProducer.Build(current,Neighbours(),Read(),"fixture",now).Length==0,"Absent/ambiguous registry merged");
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(E(m:"9A:12:34:56:78:90")),Read("fixture",Claim(m:"9A:12:34:56:78:90")),"fixture",now).Length==0,"Randomized MAC auto-linked");
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(),Read("fixture",Claim(a:"2001:db8::31")),"fixture",now).Length==0,"IPv6 fabricated");
        });
        test("Passive DNS L2 deterministic two minute continuous evidence outlives fixed neighbour confirmation then expires",()=>{
            var original=now;
            for(var seconds=0;seconds<=120;seconds+=2){
                now=original.AddSeconds(seconds);
                var rows=PassiveDnsL2BindingProducer.Build(policy,Neighbours(),Read(),"fixture",now);
                Check(rows.Single().DeviceId==id && now-Neighbours().Evidence.Single().ConfirmedAtUtc>TimeSpan.FromSeconds(15),"Continuous attribution expired with NUD age");
                Check(rows.Single().ObservedAtUtc==now,"Packet freshness not updated");
            }
            var last=Read();now=now.AddSeconds(10);
            Check(PassiveDnsL2BindingProducer.Build(policy,Neighbours(),last with{ReadAtUtc=now},"fixture",now).Length==0,"Silent device retained binding");
            now=original;
        });
        await asyncTest("Passive DNS L2 authenticated client bounded Unix IPC contract and unsupported old helper fail closed",async()=>{
            foreach(var supported in new[]{true,false}){
                var path=Path.Combine(Path.GetTempPath(),"hg-l2-"+Guid.NewGuid().ToString("N")+".sock");
                using var listener=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                listener.Bind(new UnixDomainSocketEndPoint(path));listener.Listen(1);
                try{
                    var server=Task.Run(async()=>{
                        using var peer=await listener.AcceptAsync(timeout.Token);using var stream=new NetworkStream(peer);
                        await stream.WriteAsync(Encoding.ASCII.GetBytes("HG-NETWORKVALIDATOR/2 AUTHORIZED\n"),timeout.Token);
                        using var reader=new StreamReader(stream,Encoding.UTF8,leaveOpen:true);
                        var line=await reader.ReadLineAsync(timeout.Token);using var document=System.Text.Json.JsonDocument.Parse(line!);
                        Check(document.RootElement.GetProperty("operation").GetString()=="passiveDnsRead" && document.RootElement.EnumerateObject().Count()==2,"Unexpected passive IPC request");
                        if(supported){var key=document.RootElement.GetProperty("requestId").GetString()!;
                            var bytes=System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(Read(key),new System.Text.Json.JsonSerializerOptions{PropertyNamingPolicy=System.Text.Json.JsonNamingPolicy.CamelCase});
                            await stream.WriteAsync(bytes,timeout.Token);await stream.WriteAsync(new byte[]{10},timeout.Token);}
                    });
                    var trust=new FixtureTrust();var client=new NetworkValidatorClient(path,trust);
                    var key=Guid.NewGuid().ToString("N");var read=await client.ReadPassiveDnsAsync(key,timeout.Token);await server;
                    Check(supported?read is {Complete:true} && read.RequestId==key:read is null,"Passive IPC compatibility incorrect");
                    Check(trust.Inspections==1 && trust.Authentications==1,"Passive IPC bypassed endpoint trust");
                }finally{listener.Close();File.Delete(path);}
            }
        });
        await asyncTest("Passive DNS L2 monotonic published deadline cannot be extended by wall clock rollback",async()=>{
            var store=new AddressBindingStore();var validator=new Validator(key=>Task.FromResult<PassiveDnsL2Read?>(Read(key)));
            await new PassiveDnsL2BindingProducer(store,()=>policy,()=>Neighbours(),validator,()=>now,TimeSpan.FromSeconds(1)).RefreshAsync(default);
            Check(store.Read().Observations.Length==1,"Fixture binding missing");
            await Task.Delay(1100);now=now.AddMinutes(-1);
            Check(store.Read().Observations.Length==0,"Wall rollback prolonged packet validity");now=DateTimeOffset.UtcNow;
        });
        await asyncTest("Passive DNS L2 samples evaluation clock after fresh neighbour read",async()=>{
            var original=now;var store=new AddressBindingStore();
            var validator=new Validator(key=>Task.FromResult<PassiveDnsL2Read?>(Read(key)));
            BindingEvidenceRead FreshRead(){now=now.AddMilliseconds(1);return Neighbours();}
            await new PassiveDnsL2BindingProducer(store,()=>policy,FreshRead,validator,()=>now).RefreshAsync(default);
            Check(store.Read().Observations.Length==1,"Fresh provider timestamp treated as future");now=original;
        });
        await asyncTest("Passive DNS L2 helper failure clears existing binding without blocking DNS workers",async()=>{
            var store=new AddressBindingStore();var pending=new TaskCompletionSource<PassiveDnsL2Read?>();
            var validator=new Validator(_=>pending.Task);
            var producer=new PassiveDnsL2BindingProducer(store,()=>policy,()=>Neighbours(),validator,()=>now);
            var task=producer.RefreshAsync(default);
            Check(!task.IsCompleted && store.Read().Observations.Length==0,"Background exchange leaked identity");
            pending.SetResult(null);await task;
            Check(store.Read().Observations.Length==0 && validator.ActiveRequests==0,"Unavailable helper accepted/ARP attempted");
            var good=new Validator(key=>Task.FromResult<PassiveDnsL2Read?>(Read(key)));
            await new PassiveDnsL2BindingProducer(store,()=>policy,()=>Neighbours(),good,()=>now).RefreshAsync(default);
            Check(store.Read().Observations.Length==1,"Fixture binding missing");
            await producer.RefreshAsync(default);Check(store.Read().Observations.Length==0,"Helper failure retained binding");
        });
        await asyncTest("Passive DNS L2 integrated active OFF continuous TV UDP TCP Block Restore after neighbour age exceeds fifteen seconds",async()=>{
            using var upstream=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var settings=EngineSettings.FromConfig(new EngineConfig{UpstreamDnsIpv4="127.0.0.1",UpstreamDnsPort=((IPEndPoint)upstream.Client.LocalEndPoint!).Port});
            var rules=new RuleStore("passive-l2");var app=new PolicyApplicationService(rules,new PolicyPersistence(Path.Combine(folder,"passive-l2-policy.json")));
            Check(app.ReplaceFull(new(0,policy)).Success,"Fixture policy failed");
            var processor=new DnsRequestProcessor(rules,settings,new UpstreamDnsForwarder(settings),app.State);
            FullDnsPolicy Current()=>app.State.GetSnapshot().Policy!;
            var validator=new Validator(key=>Task.FromResult<PassiveDnsL2Read?>(Read(key,Claim(),Claim("192.0.2.32",otherMac))));
            var producer=new PassiveDnsL2BindingProducer(processor.Bindings,Current,()=>Neighbours(E(),E("192.0.2.32",otherMac)),validator,()=>now);
            var activeScope=ActiveValidationScope.Parse("0",null,null,Current());
            var integrated=new ActiveBindingProducer(processor.Bindings,Current,()=>Neighbours(),validator,()=>now,true,activeScope,
                passiveRefresh:producer.RefreshAsync);
            byte[] Query(string domain){var bytes=new List<byte>{0x12,0x34,1,0,0,1,0,0,0,0,0,0};
                foreach(var label in domain.Split('.')){bytes.Add((byte)label.Length);bytes.AddRange(Encoding.ASCII.GetBytes(label));}
                bytes.AddRange(new byte[]{0,0,1,0,1});return bytes.ToArray();}
            DnsRequestContext Context(string source,DnsTransport transport)=>new(transport,source,0,now,null);
            async Task Allow(string source,DnsTransport transport){
                var answer=Task.Run(async()=>{var request=await upstream.ReceiveAsync(deadline.Token);var bytes=request.Buffer;bytes[2]=0x81;bytes[3]=0x80;await upstream.SendAsync(bytes,request.RemoteEndPoint,deadline.Token);});
                var response=await processor.ProcessAsync(Query("youtube.com"),Context(source,transport),deadline.Token);await answer;
                Check(response is not null && response[7]==0 && !processor.Observations.Read().Last().Blocked,"Expected upstream Allow missing");}
            for(var step=0;step<20;step++){
                now=DateTimeOffset.UtcNow;await integrated.RefreshAsync(deadline.Token);
                var responses=await Task.WhenAll(Enumerable.Range(0,8).Select(index=>processor.ProcessAsync(Query(index%2==0?"youtube.com":"www.youtube.com"),Context(address,index%2==0?DnsTransport.Udp:DnsTransport.Tcp),deadline.Token)));
                Check(responses.All(r=>r is not null && r[7]==1 && r.TakeLast(4).All(b=>b==0)),"Concurrent TV sinkhole response missing");
            }
            Check(!activeScope.IsActive && !integrated.Health.ActiveValidationEnabled && validator.ActiveRequests==0,"Passive enforcement enabled ARP");
            Check(processor.Observations.Read().Where(r=>r.Request.SourceAddress==address).All(r=>r.DeviceId==id && r.Blocked),"Continuous TV identity disappeared");
            await Allow("192.0.2.32",DnsTransport.Udp);Check(processor.Observations.Read().Last().DeviceId==other,"Registered control identity incorrect");
            await Allow("192.0.2.99",DnsTransport.Udp);await Allow("2001:db8::31",DnsTransport.Tcp);
            Check(app.ReplaceFull(new(app.State.GetSnapshot().Revision,Current() with{Overrides=[new(id,"youtube.com",DeviceDomainRuleState.Inherit)]})).Success,"Exact fixture Restore failed");
            await Allow(address,DnsTransport.Udp);await Allow(address,DnsTransport.Tcp);
            Check(processor.Observations.Read().Last().DeviceId==id && Current().Overrides.Single().State==DeviceDomainRuleState.Inherit,"Restore lost identity/semantics");
            var waiting=new TaskCompletionSource<PassiveDnsL2Read?>();
            var slow=new PassiveDnsL2BindingProducer(processor.Bindings,Current,()=>Neighbours(),new Validator(_=>waiting.Task),()=>now);
            var background=slow.RefreshAsync(deadline.Token);
            await Allow("192.0.2.99",DnsTransport.Udp);
            Check(!background.IsCompleted,"Fixture did not exercise in-flight helper independently of DNS");
            waiting.SetResult(null);await background;
            Check(processor.Bindings.Read().Observations.Length==0,"Failed helper retained identity");
        });
    }
}
