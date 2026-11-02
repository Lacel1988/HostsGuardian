using System.Diagnostics;
using System.Collections.Immutable;
using HostsGuardian.Core.Models;
using HostsGuardian.DnsEngine;

internal static class ReliabilityFoundationTests
{
    private sealed class Clock : TimeProvider {
        public long Tick;
        public override long TimestampFrequency=>1000;
        public override long GetTimestamp()=>Tick;
    }
    private sealed class ReorderClock : TimeProvider {
        public long Tick; public readonly ManualResetEventSlim Entered=new(), Release=new(); private int _calls;
        public override long TimestampFrequency=>1000;
        public override long GetTimestamp() { if(Interlocked.Increment(ref _calls)==1) { Entered.Set(); Release.Wait(); return 0; } return Tick; }
    }
    public static void Run(Action<string,Action> test)
    {
        void Check(bool value,string message) { if(!value)throw new Exception(message); }
        test("Concurrent delayed telemetry expires independently of FIFO timestamp order",()=>{
            var clock=new ReorderClock();var store=new DnsObservationStore(clock);
            var old=new DnsRequestContext(DnsTransport.Udp,"192.0.2.1",1,DateTimeOffset.UtcNow,null);
            var decision=new EffectivePolicyExplanation(1,0,null,"Unknown","fixture.invalid",DeviceDomainRuleState.Inherit,false,"GlobalAllow");
            var first=Task.Run(()=>store.Record(old,decision));Check(clock.Entered.Wait(5000),"Clock barrier timeout");
            try {clock.Tick=1000;store.Record(new(DnsTransport.Udp,"192.0.2.2",1,DateTimeOffset.UtcNow,null),decision);store.Read();}
            finally{clock.Release.Set();}
            first.GetAwaiter().GetResult();store.Read();clock.Tick=899999;
            Check(store.Read().Length==2,"Before-boundary retention lost");clock.Tick=900000;
            Check(store.Read().Length==1 && store.Read().All(r=>r.CorrelationId!=old.CorrelationId),"Expired tail survived FIFO purge");
            store.Complete(old,"Cancelled",null,0);Check(store.Read().Length==1,"Completion resurrected expired decision");
            clock.Tick=901000;Check(store.Read().Length==0,"Exact 15-minute boundary missed");
            clock.Tick=-1;store.Record(old,decision);clock.Tick=-2;Check(store.Read().Length==0,"Clock regression prolonged retention");
        });
        test("Immutable address index preserves scoped conflict stale unknown and registered policy semantics",()=>{
            var store=new AddressBindingStore();var now=DateTimeOffset.UtcNow;var first=Guid.NewGuid();var second=Guid.NewGuid();
            var policy=FullDnsPolicy.Empty with{Devices=[new(first,"First","02:00:00:00:00:01","fixture","Fixture"),new(second,"Second","02:00:00:00:00:02","fixture","Fixture")]};
            var rows=Enumerable.Range(0,1024).Select(i=>new AddressBindingObservation($"192.0.{i/256}.{i%256}",null,first,"Fixture",now,now.AddSeconds(10),true)).ToImmutableArray();
            store.Replace(new(0,rows.Add(new("192.0.0.1",null,second,"Conflict fixture",now,now.AddSeconds(10),true))
                .Add(new("192.0.0.2","other",second,"Scope fixture",now,now.AddSeconds(10),true))));
            foreach(var scope in new string?[]{null,"other","missing"})foreach(var source in new[]{"192.0.0.1","192.0.0.2","192.0.3.255","192.0.9.1","2001:db8::1"})foreach(var time in new[]{now,now.AddSeconds(11)}) {
                var context=new DnsRequestContext(DnsTransport.Udp,source,1,time,scope);
                Check(AddressBindingStore.Resolve(store.Read(),policy,context,time)==AddressBindingStore.Resolve(store.ReadFor(context),policy,context,time),"Index changed attribution");
                Check(store.Read().Generation==store.ReadFor(context).Generation,"Index revision changed");
            }
        });
        test("Evidence retention expires on monotonic time independently from wall clock",()=>{
            var clock=new Clock();var store=new DnsObservationStore(clock);
            store.Record(new(DnsTransport.Udp,"192.0.2.1",1,DateTimeOffset.UtcNow.AddYears(1),null),
                new(1,0,null,"Unknown","fixture.invalid",DeviceDomainRuleState.Inherit,false,"GlobalAllow"));
            Check(store.Read().Length==1,"Fixture missing");clock.Tick=900000;
            Check(store.Read().Length==0,"Wall future prolonged retention");
        });
        test("Correlated bounded evidence retains more than 64 decisions and separates transport write from client delivery",()=>{
            var store=new DnsObservationStore();
            var device=Guid.NewGuid();
            var decision=new EffectivePolicyExplanation(23,7,device,"Validated","example.invalid",DeviceDomainRuleState.Block,true,"Fixture");
            DnsRequestContext? last=null;
            var watch=Stopwatch.StartNew();
            for(var i=0;i<200;i++) {
                last=new(DnsTransport.Udp,"192.0.2.1",1000+i,DateTimeOffset.UtcNow.AddDays(-1),null);
                store.Record(last,decision,1);
                store.Complete(last,"ResponsePrepared",new byte[12],1.2);
                if(i%20==0)store.Read();
            }
            var rows=store.Read();
            Check(rows.Length>64,"Acceptance evidence still limited to 64");
            Check(rows.Select(r=>r.CorrelationId).Distinct().Count()==rows.Length,"Correlation alias");
            Check(rows.All(r=>r.PolicyRevision==23 && r.MappingGeneration==7 && r.QueryType==1),"Evidence fields lost");
            store.Complete(last!,"TransportWriteSucceeded",new byte[12],2.3);
            var final=store.Read().Single(r=>r.CorrelationId==last!.CorrelationId);
            Check(final.ResponseState=="TransportWriteSucceeded" && final.ProcessingMilliseconds==1.2,"Completion correlation incorrect");
            Check(rows.Zip(rows.Skip(1)).All(pair=>pair.First.Sequence<pair.Second.Sequence),"Monotonic sequence lost");
            Console.WriteLine($"MEASURE 200 correlated evidence records {watch.Elapsed.TotalMilliseconds:F1} ms; dropped={store.Dropped}");
        });
        test("Telemetry overflow remains bounded and observable without blocking producers",()=>{
            var store=new DnsObservationStore();
            var decision=new EffectivePolicyExplanation(1,0,null,"Unknown","fixture.invalid",DeviceDomainRuleState.Inherit,false,"GlobalAllow");
            Parallel.For(0,20000,i=>store.Record(new(DnsTransport.Tcp,"192.0.2.1",1,DateTimeOffset.UtcNow,null),decision,28));
            var rows=store.Read();
            Check(rows.Length<=DnsObservationStore.Capacity,"Unbounded retention");
            Check(store.Dropped+store.Evicted>0,"Overflow concealed");
            Check(rows.All(r=>r.DeviceId is null && !r.Blocked),"Telemetry fabricated identity");
        });
        test("IPv6 address format and privacy addresses never authorize unsupported DeviceId",()=>{
            var id=Guid.NewGuid();var now=DateTimeOffset.UtcNow;
            var policy=FullDnsPolicy.Empty with{Devices=[new(id,"Fixture","02:00:00:00:00:01","fixture","Explicit")]};
            foreach(var address in new[]{"2001:db8::1","2001:db8:2::1234","fe80::200:ff:fe00:1"}) {
                var read=new BindingRead(1,[new(address,null,id,"Untrusted IPv6 fixture",now,now.AddSeconds(10),true)]);
                var result=AddressBindingStore.Resolve(read,policy,new(DnsTransport.Udp,address,1,now,null),now);
                Check(result.DeviceId is null && result.State=="UnsupportedAddressFamily","Address-derived IPv6 identity");
            }
        });
    }
}
