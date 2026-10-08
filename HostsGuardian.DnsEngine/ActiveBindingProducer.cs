using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.DnsEngine;

/// <summary>Bounded active-evidence cache. Publication is immutable; DNS only reads the store.</summary>
public sealed class ActiveBindingProducer(AddressBindingStore store,Func<FullDnsPolicy> policy,
    Func<BindingEvidenceRead> evidence,IEndpointValidator validator,Func<DateTimeOffset>? clock=null,bool activeValidationEnabled=false,
    ActiveValidationScope? scope=null,Action? passiveFallback=null)
{
    private ValidatorHealth _health=new("UNKNOWN","Not checked",false,DateTimeOffset.MinValue);
    public ValidatorHealth Health=>Volatile.Read(ref _health);
    private readonly Dictionary<(string,string),(EndpointValidationResult Result,Guid Device,string RegisteredMac)> _accepted=new();
    private readonly Dictionary<(string,string),DateTimeOffset> _attempts=new();
    private DateTimeOffset Now=>clock?.Invoke() ?? DateTimeOffset.UtcNow;
    private bool Active=>activeValidationEnabled && scope?.IsActive==true;
    private void UpdateHealth(bool ready)
    {
        var active=Active;
        Volatile.Write(ref _health,new(ready?"READY":"UNAVAILABLE",ready?"Authenticated IPC; "+(active?"scoped active validation":"passive only"):validator.FailureReason,active,Now)
        {Mode=active?"ScopedActive":"Passive",ApprovedTargetCount=scope?.Devices.Count ?? 0,DeadlineUtc=scope?.DeadlineUtc,
            RemainingSeconds=scope?.RemainingSeconds ?? 0,ModeReason=scope?.Reason ?? "Explicit scope required"});
    }
    private void Passive()
    {
        _accepted.Clear();
        if(passiveFallback is not null)try{passiveFallback();}catch{store.PublishObserved([]);}
    }
    public static bool ValidResult(EndpointValidationRequest request,EndpointValidationResult? result,DateTimeOffset now)
    {
        return result is not null && result.RequestId==request.RequestId && result.Address==request.Address && result.Interface==request.Interface &&
            result.Method=="TargetedARP" && result.Outcome=="Confirmed" && result.Macs is {Length:1} && result.Macs[0] is {Length:17} &&
            DevicePolicyIdentity.NormalizeMac(result.Macs[0])==result.Macs[0] && result.Macs[0]!="00:00:00:00:00:00" &&
            byte.TryParse(result.Macs[0][..2],System.Globalization.NumberStyles.HexNumber,null,out var first) && (first&1)==0 &&
            result.RequestedAtUtc<=result.ObservedAtUtc && result.RequestedAtUtc>=now.AddSeconds(-4) && result.ObservedAtUtc<=now &&
            result.ConfirmedAtUtc==result.ObservedAtUtc && result.ValidatedAtUtc>=result.ConfirmedAtUtc && result.ValidatedAtUtc<=now &&
            result.ExpiresAtUtc>now && result.ExpiresAtUtc<=result.ConfirmedAtUtc.Value.AddSeconds(45);
    }
    public async Task RefreshAsync(CancellationToken cancellation)
    {
        scope?.ValidateRegistry(policy());
        if(!Active)Passive();
        var ready=await validator.ProbeAsync(cancellation);
        UpdateHealth(ready);
        if(!Active){Passive();return;} // Health-only never sends ARP.
        var now=Now;var current=policy();BindingEvidenceRead read;
        try{read=evidence();}catch{read=new(now,false,[]);}
        var candidates=read.Complete && read.Evidence.Length<64 && read.ReadAtUtc<=now && now-read.ReadAtUtc<TimeSpan.FromSeconds(20) ? read.Evidence.GroupBy(e=>e.Address)
            .Where(g=>IPAddress.TryParse(g.Key,out var ip) && ip.AddressFamily==AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any) && ip.GetAddressBytes()[0]<224)
            .Where(g=>g.Count()==1 && !g.Single().NeighborState.Split('/').Any(s=>s is "FAILED" or "INCOMPLETE") && g.Single().Interface!="")
            .Select(g=>g.Single()).Where(e=>RegisteredMacCorrelation.Find(current,[e.Mac],read.Evidence.Count(x=>DevicePolicyIdentity.NormalizeMac(x.Mac)==DevicePolicyIdentity.NormalizeMac(e.Mac)),true) is {} registration && scope!.Devices.Contains(registration.DeviceId))
            .Take(64).ToArray():[];
        foreach(var key in _accepted.Keys.ToArray())
        {
            var value=_accepted[key];var row=candidates.FirstOrDefault(e=>(e.Interface,e.Address)==key);
            var registration=current.Devices.FirstOrDefault(d=>d.DeviceId==value.Device);
            if(value.Result.ExpiresAtUtc<=now || row is null || registration is null || DevicePolicyIdentity.NormalizeMac(registration.Mac)!=value.RegisteredMac ||
               DevicePolicyIdentity.NormalizeMac(row.Mac)!=value.RegisteredMac)_accepted.Remove(key);
        }
        Publish(); // Invalidate before awaiting any helper response.
        var keys=candidates.Select(e=>(e.Interface,e.Address)).ToHashSet();
        foreach(var key in _attempts.Keys.Where(k=>!keys.Contains(k)).ToArray())_attempts.Remove(key);
        // Two exact candidates per refresh, no subnet sweep. Oldest attempt first prevents starvation.
        var due=ready?candidates.Where(e=>!_attempts.TryGetValue((e.Interface,e.Address),out var last) || now-last>=TimeSpan.FromSeconds(30))
            .OrderBy(e=>_attempts.GetValueOrDefault((e.Interface,e.Address),DateTimeOffset.MinValue)).Take(2).ToArray():[];
        foreach(var row in due)
        {
            scope!.ValidateRegistry(policy());
            if(!Active || scope.RemainingSeconds<3)break; // Do not start work without the full bounded exchange budget.
            if(_attempts.Count>=64 && !_attempts.ContainsKey((row.Interface,row.Address)))break;
            var key=(row.Interface,row.Address);_attempts[key]=now;
            var registration=RegisteredMacCorrelation.Find(current,[row.Mac],read.Evidence.Count(x=>DevicePolicyIdentity.NormalizeMac(x.Mac)==DevicePolicyIdentity.NormalizeMac(row.Mac)),true)!;
            var request=new EndpointValidationRequest(Guid.NewGuid().ToString("N"),row.Address,row.Interface);
            EndpointValidationResult? result;
            try{using var bounded=CancellationTokenSource.CreateLinkedTokenSource(cancellation);bounded.CancelAfter(TimeSpan.FromSeconds(Math.Min(3,scope.RemainingSeconds)));result=await validator.ValidateAsync(request,bounded.Token).WaitAsync(bounded.Token);}catch{result=null;}
            var latest=policy();var latestRead=evidence();var latestRow=latestRead.Evidence.Where(e=>e.Address==row.Address).ToArray();
            scope.ValidateRegistry(latest);
            if(Active && scope.Devices.Contains(registration.DeviceId) && ValidResult(request,result,Now) && latestRead.Complete && latestRead.Evidence.Length<64 && latestRead.ReadAtUtc<=Now && Now-latestRead.ReadAtUtc<TimeSpan.FromSeconds(20) && latestRow.Length==1 && !latestRow[0].NeighborState.Split('/').Any(s=>s is "FAILED" or "INCOMPLETE") && latestRow[0].Interface==row.Interface &&
               DevicePolicyIdentity.NormalizeMac(latestRow[0].Mac)==result!.Macs[0] && RegisteredMacCorrelation.Find(latest,[result.Macs[0]],latestRead.Evidence.Count(e=>DevicePolicyIdentity.NormalizeMac(e.Mac)==result.Macs[0]),true)?.DeviceId==registration.DeviceId)
                _accepted[key]=(result!,registration.DeviceId,result!.Macs[0]);
            else _accepted.Remove(key);
        }
        Publish();
        UpdateHealth(ready);
    }
    private void Publish()
    {
        if(!Active){Passive();return;}
        var now=Now;var current=policy();
        store.PublishObserved(_accepted.Values.Where(v=>v.Result.ExpiresAtUtc>now && current.Devices.Any(d=>d.DeviceId==v.Device && DevicePolicyIdentity.NormalizeMac(d.Mac)==v.RegisteredMac))
            .Select(v=>new AddressBindingObservation(v.Result.Address,null,v.Device,"OBSERVED: targeted ARP; current unauthenticated network claim",v.Result.ObservedAtUtc,v.Result.ExpiresAtUtc,true)
            {MacEvidence=v.RegisteredMac,Interface=v.Result.Interface,ValidatedAtUtc=v.Result.ValidatedAtUtc,ValidationMethod=v.Result.Method}).ToImmutableArray(),()=>Active);
    }
    public async Task RunAsync(CancellationToken cancellation)
    {
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(2));
        using var deadlineStop=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var expiry=Task.Run(async()=>{
            try {
                while(Active)await Task.Delay(TimeSpan.FromSeconds(Math.Min(.1,scope!.RemainingSeconds)),deadlineStop.Token);
                if(!deadlineStop.IsCancellationRequested && passiveFallback is not null) {
                    // Independent of an in-flight IPC exchange; DNS's snapshot guard
                    // already rejects active bindings at the monotonic deadline.
                    try{passiveFallback();}catch{store.PublishObserved([]);}
                    UpdateHealth(Health.State=="READY");
                }
            }catch(OperationCanceledException) when(deadlineStop.IsCancellationRequested){}
        },deadlineStop.Token);
        try{do{try{await RefreshAsync(cancellation);}catch(OperationCanceledException) when(cancellation.IsCancellationRequested){break;}catch{UpdateHealth(false);if(activeValidationEnabled){_accepted.Clear();store.PublishObserved([]);}if(!Active)Passive();}}while(await timer.WaitForNextTickAsync(cancellation));}
        catch(OperationCanceledException) when(cancellation.IsCancellationRequested){}
        finally{deadlineStop.Cancel();try{await expiry;}catch(OperationCanceledException){}if(activeValidationEnabled)store.PublishObserved([]);}
    }
}
