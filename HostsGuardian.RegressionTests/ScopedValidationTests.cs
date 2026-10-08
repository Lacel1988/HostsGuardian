using System.Collections.Immutable;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class ScopedValidationTests
{
    private sealed class Validator(Func<EndpointValidationRequest,Task<EndpointValidationResult?>> response,bool ready=true):IEndpointValidator
    {
        public readonly List<EndpointValidationRequest> Requests=[];
        public Task<bool> ProbeAsync(CancellationToken ct)=>Task.FromResult(ready);
        public Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest r,CancellationToken ct){Requests.Add(r);return response(r);}
    }
    public static async Task Run(Action<string,Action> test,Func<string,Func<Task>,Task> asyncTest)
    {
        void Check(bool value,string message){if(!value)throw new Exception(message);}
        var now=DateTimeOffset.UtcNow;double ticks=0;
        var a=new DeviceRegistration(Guid.NewGuid(),"Approved","00:11:22:33:44:55","fixture","User");
        var b=new DeviceRegistration(Guid.NewGuid(),"Unapproved","00:11:22:33:44:66","fixture","User");
        var policy=FullDnsPolicy.Empty with{Devices=[a,b]};
        NetworkIdentityEvidence Row(string ip,string mac)=>new(ip,mac,"","Fixture",now){Interface="fixture0",NeighborState="STALE",ReadAtUtc=now};
        var read=new BindingEvidenceRead(now,true,[Row("192.0.2.20",a.Mac!),Row("192.0.2.21",b.Mac!)]);
        ActiveValidationScope Scope(string? ids=null)=>ActiveValidationScope.Parse("1",ids ?? a.DeviceId.ToString("D"),"10",policy,()=>ticks);
        EndpointValidationResult Result(EndpointValidationRequest r)=>new(r.RequestId,r.Address,r.Interface,now,now,now,now,now.AddSeconds(45),"TargetedARP","Confirmed",[a.Mac!],"Fixture");
        test("Startup scope uses restored persistent registrations before background validation",()=>{
            var folder=Path.Combine(Path.GetTempPath(),"hg-scoped-startup-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
            try {
                var persistence=new PolicyPersistence(Path.Combine(folder,"policy.json"));
                persistence.Commit(new(23,[]){Policy=policy},false);
                var restored=new PolicyApplicationService(new RuleStore("fixture"),persistence);
                restored.InitializeForStartup();restored.InitializeForStartup();
                Check(ActiveValidationScope.Parse("1",a.DeviceId.ToString(),"10",restored.State.GetSnapshot().Policy!,()=>0).IsActive,"Restored registration rejected");
            }finally{Directory.Delete(folder,true);}
        });
        test("Scoped configuration rejects empty malformed duplicate unknown duration and global switch",()=>{
            foreach(var ids in new[]{"","bad",Guid.NewGuid().ToString(),a.DeviceId+","+a.DeviceId,Guid.Empty.ToString()})
                Check(!ActiveValidationScope.Parse("1",ids,"10",policy,()=>ticks).IsActive,"Unsafe scope");
            foreach(var duration in new[]{null,"0","4","301","bad","-1"})
                Check(!ActiveValidationScope.Parse("1",a.DeviceId.ToString(),duration,policy,()=>ticks).IsActive,"Unsafe duration");
            Check(!ActiveValidationScope.Parse("1",null,null,policy,()=>ticks).IsActive,"Global fallback");
            Check(!ActiveValidationScope.Parse("0",a.DeviceId.ToString(),"10",policy,()=>ticks).IsActive,"OFF ignored");
            Check(!ActiveValidationScope.Parse("true",a.DeviceId.ToString(),"10",policy,()=>ticks).IsActive,"Invalid flag");
        });
        await asyncTest("One approved DeviceId never probes other registered devices; expiry atomically hides active bindings",async()=>{
            ticks=0;var scope=Scope();var store=new AddressBindingStore();var validator=new Validator(r=>Task.FromResult<EndpointValidationResult?>(Result(r)));
            var passiveCalls=0;
            var producer=new ActiveBindingProducer(store,()=>policy,()=>read,validator,()=>now,true,scope,()=>{passiveCalls++;store.Replace(new(store.Read().Generation,[]));});
            await producer.RefreshAsync(default);
            Check(validator.Requests.Count==1 && validator.Requests[0].Address=="192.0.2.20","Unapproved probe");
            Check(AddressBindingStore.Resolve(store.Read(),policy,new(DnsTransport.Udp,"192.0.2.20",0,now,null),now).DeviceId==a.DeviceId,"No approved binding");
            ticks=10;
            Check(store.Read().Observations.Length==0,"Active binding outlived monotonic deadline with frozen wall clock");
            await producer.RefreshAsync(default);
            Check(passiveCalls>0 && validator.Requests.Count==1 && producer.Health.Mode=="Passive" && producer.Health.ModeReason=="Expired","No passive expiry");
        });
        await asyncTest("DNS reads stay independent of in-flight validation and late results cannot extend approval",async()=>{
            ticks=0;var scope=Scope();var store=new AddressBindingStore();var reply=new TaskCompletionSource<EndpointValidationResult?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var validator=new Validator(_=>reply.Task);var fallback=0;
            var producer=new ActiveBindingProducer(store,()=>policy,()=>read,validator,()=>now,true,scope,()=>fallback++);
            var refresh=producer.RefreshAsync(default);
            Check(validator.Requests.Count==1 && !refresh.IsCompleted,"Fixture not in flight");
            Check(AddressBindingStore.Resolve(store.Read(),policy,new(DnsTransport.Tcp,"192.0.2.20",0,now,null),now).DeviceId==null,"DNS awaited validator");
            ticks=11;reply.SetResult(Result(validator.Requests[0]));await refresh;
            Check(store.Read().Observations.Length==0 && fallback>0,"Late result accepted");
        });
        await asyncTest("Unknown missing ambiguous randomized reused and unavailable targets fail closed",async()=>{
            foreach(var scenario in new[]{"missing","duplicate-registry","duplicate-ip","randomized","reuse","helper","ipv6","legacy"})
            {
                ticks=0;var scope=Scope();var current=policy;var evidence=read;
                if(scenario=="missing")current=policy with{Devices=[b]};
                if(scenario=="duplicate-registry")current=policy with{Devices=[a,a,b]};
                if(scenario=="duplicate-ip")evidence=read with{Evidence=[read.Evidence[0],Row("192.0.2.20",b.Mac!)]};
                if(scenario is "randomized" or "reuse")evidence=read with{Evidence=[Row("192.0.2.20","02:11:22:33:44:99")]};
                if(scenario=="ipv6")evidence=read with{Evidence=[Row("2001:db8::20",a.Mac!)]};
                var store=new AddressBindingStore();var validator=new Validator(r=>Task.FromResult<EndpointValidationResult?>(Result(r)),scenario!="helper");
                var producer=new ActiveBindingProducer(store,()=>current,()=>evidence,validator,()=>now,true,scenario=="legacy"?null:scope);
                await producer.RefreshAsync(default);
                Check(validator.Requests.Count==0 && store.Read().Observations.Length==0,"Unsafe target: "+scenario);
            }
        });
        test("Monotonic failure and backward clock disable probing permanently",()=>{
            ticks=0;var scope=Scope();ticks=1;Check(scope.IsActive,"Initial clock");ticks=.5;Check(!scope.IsActive,"Backward clock accepted");ticks=2;Check(!scope.IsActive,"Clock recovered into active mode");
            var broken=ActiveValidationScope.Parse("1",a.DeviceId.ToString(),"10",policy,()=>double.NaN);Check(!broken.IsActive,"NaN accepted");
            broken=ActiveValidationScope.Parse("1",a.DeviceId.ToString(),"10",policy,()=>throw new InvalidOperationException());Check(!broken.IsActive,"Clock exception accepted");
        });
        await asyncTest("Expired active mode restores fresh passive evidence without restart or active lease retention",async()=>{
            ticks=0;var scope=Scope();var store=new AddressBindingStore();var validator=new Validator(r=>Task.FromResult<EndpointValidationResult?>(Result(r)));
            var passiveRead=read with{Evidence=[read.Evidence[0] with{NeighborState="REACHABLE",ConfirmedAtUtc=now,Confidence="OBSERVED"}]};
            var passive=new ValidatedBindingProducer(store,()=>policy,()=>passiveRead,()=>now);
            var producer=new ActiveBindingProducer(store,()=>policy,()=>read,validator,()=>now,true,scope,passive.Refresh);
            await producer.RefreshAsync(default);ticks=10;await producer.RefreshAsync(default);
            Check(store.Read().Observations.Length==1 && store.Read().Observations[0].ValidationMethod!="TargetedARP","Passive not restored");
            Check(validator.Requests.Count==1 && !producer.Health.ActiveValidationEnabled,"Expiry still probes");
        });
        await asyncTest("Deadline watchdog restores passive production while IPC is still in flight",async()=>{
            ticks=0;var scope=Scope();var store=new AddressBindingStore();
            var started=new TaskCompletionSource<EndpointValidationRequest>(TaskCreationOptions.RunContinuationsAsynchronously);
            var reply=new TaskCompletionSource<EndpointValidationResult?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var fallback=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var validator=new Validator(r=>{started.TrySetResult(r);return reply.Task;});
            var producer=new ActiveBindingProducer(store,()=>policy,()=>read,validator,()=>now,true,scope,()=>fallback.TrySetResult());
            using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var running=producer.RunAsync(stop.Token);
            var request=await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
            ticks=10;
            await fallback.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Check(!reply.Task.IsCompleted && store.Read().Observations.Length==0,"Fallback waited for IPC");
            reply.SetResult(Result(request));stop.Cancel();await running;
            Check(store.Read().Observations.Length==0,"Late IPC revived active state");
        });
        await asyncTest("Insufficient remaining exchange budget starts no new probe",async()=>{
            ticks=0;var scope=Scope();ticks=8;var validator=new Validator(r=>Task.FromResult<EndpointValidationResult?>(Result(r)));
            await new ActiveBindingProducer(new(),()=>policy,()=>read,validator,()=>now,true,scope).RefreshAsync(default);
            Check(validator.Requests.Count==0,"Probe started too close to deadline");
        });
        await asyncTest("Neighbour failure during in-flight confirmation cannot create a binding",async()=>{
            ticks=0;var scope=Scope();var current=read;var store=new AddressBindingStore();
            var validator=new Validator(r=>{
                current=current with{Evidence=[current.Evidence[0] with{NeighborState="STALE/FAILED"}]};
                return Task.FromResult<EndpointValidationResult?>(Result(r));
            });
            await new ActiveBindingProducer(store,()=>policy,()=>current,validator,()=>now,true,scope).RefreshAsync(default);
            Check(store.Read().Observations.Length==0,"Failed neighbour accepted");
        });
    }
}
