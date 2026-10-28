using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class RequestBindingRefreshTests
{
    private sealed class Validator(Func<string,CancellationToken,Task<PassiveDnsL2Read?>> read):IEndpointValidator
    {
        public int Reads,Active;
        public Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest request,CancellationToken token)
        { Active++; throw new Exception("Active probing forbidden"); }
        public Task<PassiveDnsL2Read?> ReadPassiveDnsAsync(string id,CancellationToken token)
        { Interlocked.Increment(ref Reads); return read(id,token); }
    }
    public static async Task Run(Func<string,Func<Task>,Task> test,string folder)
    {
        void Check(bool b,string m){if(!b)throw new Exception(m);}
        await test("Staggered devices refresh after completed shared window rather than reuse pre-packet evidence",async()=>{
            var reads=0;
            var refresh=new RequestBindingRefresh(_=>{Interlocked.Increment(ref reads);return Task.CompletedTask;});
            var first=new DnsRequestContext(DnsTransport.Udp,"192.0.2.1",1,DateTimeOffset.UtcNow,null);
            await refresh.EnsureAsync(first,default);
            var before=reads;var watch=Stopwatch.StartNew();
            await refresh.EnsureAsync(first with{SourceAddress="192.0.2.2"},default);
            Check(reads>before,"Staggered device reused completed pre-packet refresh");
            Check(watch.Elapsed<TimeSpan.FromMilliseconds(400),"Staggered refresh unbounded");
        });
        await test("Late staggered device gets its own post-packet evidence without cross-device reuse",async()=>{
            var ready=new System.Collections.Concurrent.ConcurrentDictionary<string,bool>();var reads=0;
            var refresh=new RequestBindingRefresh(_=>{if(Interlocked.Increment(ref reads)>3)ready["192.0.2.2"]=true;return Task.CompletedTask;},c=>ready.ContainsKey(c.SourceAddress));
            var a=new DnsRequestContext(DnsTransport.Udp,"192.0.2.1",1,DateTimeOffset.UtcNow,null);
            var first=refresh.EnsureAsync(a,default);
            while(Volatile.Read(ref reads)<3)await Task.Delay(1);
            var watch=Stopwatch.StartNew();await refresh.EnsureAsync(a with{SourceAddress="192.0.2.2"},default);await first;
            Check(ready.ContainsKey("192.0.2.2") && !ready.ContainsKey(a.SourceAddress),"Late device missed refresh or cross-device evidence reused");
            Check(watch.Elapsed<TimeSpan.FromMilliseconds(400),"Per-request bound lost");
        });
        await test("Request binding expired snapshot refresh precedes actual UDP TCP A AAAA Block and isolates controls",async()=>{
            using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var upstream=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            var settings=EngineSettings.FromConfig(new EngineConfig{UpstreamDnsIpv4="127.0.0.1",UpstreamDnsPort=((IPEndPoint)upstream.Client.LocalEndPoint!).Port});
            var rules=new RuleStore("request-refresh");
            var app=new PolicyApplicationService(rules,new PolicyPersistence(Path.Combine(folder,"request-refresh.json")));
            var device=Guid.NewGuid();const string mac="02:AB:CD:01:02:03",ip="192.0.2.31";
            var policy=FullDnsPolicy.Empty with{Devices=[new(device,"Fixture",mac,"fixture","Explicit")],Overrides=[new(device,"index.hu",DeviceDomainRuleState.Block)]};
            Check(app.ReplaceFull(new(0,policy)).Success,"Policy fixture failed");
            var processor=new DnsRequestProcessor(rules,settings,new UpstreamDnsForwarder(settings),app.State);
            var captured=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var scenario="fresh";var readCount=0;
            var validator=new Validator(async(id,token)=>{
                await captured.Task.WaitAsync(token);
                var now=DateTimeOffset.UtcNow;
                var count=Interlocked.Increment(ref readCount);
                if(scenario=="unavailable")throw new IOException("Fixture helper unavailable");
                if(scenario=="timeout")await Task.Delay(Timeout.Infinite,token);
                if(scenario=="delayed" && count==1)return new(id,"PassiveDnsL2",true,now,"Capture pending",[]);
                if(scenario=="stale")return new(id,"PassiveDnsL2",true,now,"Stale",[new(ip,mac,"fixture0",now.AddSeconds(-11),now.AddSeconds(-1))]);
                if(scenario=="conflict")return new(id,"PassiveDnsL2",true,now,"Conflict",[new(ip,mac,"fixture0",now,now.AddSeconds(10)),new(ip,"02:AB:CD:04:05:06","fixture0",now,now.AddSeconds(10))]);
                return new(id,"PassiveDnsL2",true,now,"Fixture",[new(ip,mac,"fixture0",now,now.AddSeconds(10))]);
            });
            BindingEvidenceRead Neighbours(){var now=DateTimeOffset.UtcNow;return new(now,true,[new(ip,mac,"","OBSERVED",now.AddMinutes(-1)){Interface="fixture0",NeighborState="STALE",ReadAtUtc=now}]);}
            var producer=new PassiveDnsL2BindingProducer(processor.Bindings,()=>app.State.GetSnapshot().Policy!,Neighbours,validator);
            processor.BindingRefresh=new(producer.RefreshAsync);
            byte[] Query(int type){var b=new List<byte>{0x12,0x34,1,0,0,1,0,0,0,0,0,0};foreach(var label in "www.index.hu".Split('.')){b.Add((byte)label.Length);b.AddRange(Encoding.ASCII.GetBytes(label));}b.AddRange([0,0,(byte)type,0,1]);return b.ToArray();}
            var now=DateTimeOffset.UtcNow;
            processor.Bindings.Replace(new(processor.Bindings.Read().Generation,[new(ip,null,device,"Expired fixture",now.AddSeconds(-20),now.AddSeconds(-10),true){MacEvidence=mac}]));
            var requests=Enumerable.Range(0,12).Select(i=>processor.ProcessAsync(Query(i%2==0?1:28),new(i%2==0?DnsTransport.Udp:DnsTransport.Tcp,ip,12000+i,DateTimeOffset.UtcNow,null),stop.Token)).ToArray();
            Check(!Task.WhenAll(requests).IsCompleted,"DNS decided before L2 was ready");
            captured.SetResult();var watch=Stopwatch.StartNew();var responses=await Task.WhenAll(requests);
            Check(responses.Select((r,i)=>r is not null && (r[2]&0x80)!=0 &&
                (i%2==0 ? r[7]==1 && r.TakeLast(4).All(x=>x==0) : r[7]==0 && r.Length==Query(28).Length)).All(x=>x),"Real sinkhole A/empty AAAA response missing");
            Check(processor.Observations.Read().All(o=>o.DeviceId==device && o.Blocked),"Decision used stale snapshot");
            Check(validator.Reads<=3 && validator.Active==0,"Parallel requests amplified IPC or probed ARP");
            Console.WriteLine($"MEASURE concurrent refresh completion {watch.Elapsed.TotalMilliseconds:F1} ms; IPC reads={validator.Reads}");
            async Task Allow(string source){var reply=Task.Run(async()=>{var q=await upstream.ReceiveAsync(stop.Token);q.Buffer[2]=0x81;q.Buffer[3]=0x80;await upstream.SendAsync(q.Buffer,q.RemoteEndPoint,stop.Token);});var r=await processor.ProcessAsync(Query(1),new(DnsTransport.Udp,source,10000,DateTimeOffset.UtcNow,null),stop.Token);await reply;Check(r is not null && !processor.Observations.Read().Last().Blocked,"Unrelated client blocked");}
            await Allow("192.0.2.99");await Allow("2001:db8::31");
            foreach(var failure in new[]{"stale","conflict","unavailable","timeout"}){
                scenario=failure;readCount=0;processor.Bindings.Replace(new(processor.Bindings.Read().Generation,[]));
                processor.BindingRefresh=new(producer.RefreshAsync);await Allow(ip);
                Check(processor.Observations.Read().Last().DeviceId is null,$"{failure} authorized identity");
            }
            scenario="delayed";readCount=0;processor.Bindings.Replace(new(processor.Bindings.Read().Generation,[]));processor.BindingRefresh=new(producer.RefreshAsync);
            var delayed=await processor.ProcessAsync(Query(1),new(DnsTransport.Udp,ip,10000,DateTimeOffset.UtcNow,null),stop.Token);
            Check(delayed is not null && delayed[7]==1 && processor.Observations.Read().Last().DeviceId==device && readCount==3,"Delayed capture not included before decision");
            Check(app.ReplaceFull(new(app.State.GetSnapshot().Revision,policy with{Overrides=[]})).Success,"Restore failed");await Allow(ip);
            Check(processor.Observations.Read().Last().DeviceId==device,"Restore erased valid identity");
        });
        await test("Request refresh delayed evidence is retried within bounded shared window",async()=>{
            var attempts=0;var refresh=new RequestBindingRefresh(_=>{Interlocked.Increment(ref attempts);return Task.CompletedTask;});
            await Task.WhenAll(Enumerable.Range(0,32).Select(_=>refresh.EnsureAsync(new(DnsTransport.Udp,"192.0.2.1",1,DateTimeOffset.UtcNow,null),CancellationToken.None)));
            Check(attempts==3,"Single-flight/retry limit failed");
        });
        await test("Request helper timeout and cancellation do not delay DNS without bound or publish late identity",async()=>{
            var completion=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var refresh=new RequestBindingRefresh(_=>completion.Task);
            var watch=Stopwatch.StartNew();await refresh.EnsureAsync(new(DnsTransport.Udp,"192.0.2.1",1,DateTimeOffset.UtcNow,null),CancellationToken.None);
            Check(watch.Elapsed<TimeSpan.FromSeconds(1),"Helper blocked beyond bound");Console.WriteLine($"MEASURE helper timeout {watch.Elapsed.TotalMilliseconds:F1} ms (200ms budget + scheduler tolerance)");
            using var cancelled=new CancellationTokenSource();cancelled.Cancel();
            try{await refresh.EnsureAsync(new(DnsTransport.Tcp,"192.0.2.1",1,DateTimeOffset.UtcNow,null),cancelled.Token);throw new Exception("Cancellation lost");}catch(OperationCanceledException){}
            completion.SetResult();
            var reads=0;var ipv6=new RequestBindingRefresh(_=>{reads++;return Task.CompletedTask;});await ipv6.EnsureAsync(new(DnsTransport.Udp,"2001:db8::1",1,DateTimeOffset.UtcNow,null),CancellationToken.None);Check(reads==0,"IPv6 identity fabricated");
        });
        await test("Cancelled passive refresh cannot publish a late noncooperative helper result",async()=>{
            var store=new AddressBindingStore();var device=Guid.NewGuid();const string mac="02:AB:CD:01:02:03",ip="192.0.2.31";
            var policy=FullDnsPolicy.Empty with{Devices=[new(device,"Fixture",mac,"fixture","Explicit")]};
            var late=new TaskCompletionSource<PassiveDnsL2Read?>(TaskCreationOptions.RunContinuationsAsynchronously);string request="";
            var validator=new Validator((id,token)=>{request=id;return late.Task;});
            var producer=new PassiveDnsL2BindingProducer(store,()=>policy,()=>{var now=DateTimeOffset.UtcNow;return new(now,true,[new(ip,mac,"","OBSERVED",now){Interface="fixture0",NeighborState="STALE",ReadAtUtc=now}]);},validator);
            using var cancel=new CancellationTokenSource();var work=producer.RefreshAsync(cancel.Token);cancel.Cancel();await work;
            var now=DateTimeOffset.UtcNow;late.SetResult(new(request,"PassiveDnsL2",true,now,"Late",[new(ip,mac,"fixture0",now,now.AddSeconds(10))]));
            Check(store.Read().Observations.Length==0,"Late evidence published after request deadline");
        });
    }
}
