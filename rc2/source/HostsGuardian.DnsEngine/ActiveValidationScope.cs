using System.Diagnostics;
using System.Collections.Immutable;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

/// <summary>Startup-only explicit approval. Invalid configuration never means global approval.</summary>
public sealed class ActiveValidationScope
{
    private readonly Func<double> _seconds;
    private readonly double _start;
    private double _last;
    private readonly object _gate=new();
    public ImmutableHashSet<Guid> Devices {get;}
    public int DurationSeconds {get;}
    public string Reason {get;private set;}
    public DateTimeOffset? DeadlineUtc {get;}
    private ActiveValidationScope(ImmutableHashSet<Guid> devices,int duration,string reason,Func<double>? seconds)
    {
        Devices=devices;DurationSeconds=duration;Reason=reason;
        _seconds=seconds ?? (()=>(double)Stopwatch.GetTimestamp()/Stopwatch.Frequency);
        try {_start=_last=_seconds();if(!double.IsFinite(_start))Reason="Invalid monotonic clock";}
        catch {Reason="Monotonic clock unavailable";}
        if(reason=="Active")DeadlineUtc=DateTimeOffset.UtcNow.AddSeconds(duration);
    }
    public static ActiveValidationScope Parse(string? enabled,string? targets,string? duration,FullDnsPolicy policy,Func<double>? seconds=null)
    {
        var ids=ImmutableHashSet<Guid>.Empty;var count=0;var reason="Disabled";
        if(enabled=="1")
        {
            var parts=(targets ?? "").Split(',',StringSplitOptions.None);
            var valid=parts.Length is >0 and <=64;
            foreach(var part in parts) {
                if(!Guid.TryParseExact(part,"D",out var id) || !part.Equals(id.ToString("D"),StringComparison.OrdinalIgnoreCase) || id==Guid.Empty || ids.Contains(id)) {valid=false;break;}
                ids=ids.Add(id);
            }
            valid=valid && int.TryParse(duration,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out count) && count is >=5 and <=300;
            valid=valid && ids.All(id=>policy.Devices.Count(d=>d.DeviceId==id)==1);
            reason=valid?"Active":"Invalid scope or duration; passive only";
            if(!valid){ids=ImmutableHashSet<Guid>.Empty;count=0;}
        }
        else if(enabled is not (null or "" or "0"))reason="Invalid activation flag; passive only";
        return new(ids,count,reason,seconds);
    }
    public double RemainingSeconds
    {
        get {lock(_gate) {
            if(Reason!="Active")return 0;
            double now;try{now=_seconds();}catch{Reason="Monotonic clock unavailable";return 0;}
            if(!double.IsFinite(now) || now<_last){Reason="Invalid monotonic clock";return 0;}
            _last=now;var remaining=DurationSeconds-(now-_start);
            if(remaining<=0){Reason="Expired";return 0;}
            return remaining;
        }}
    }
    public bool IsActive=>RemainingSeconds>0;
    public void ValidateRegistry(FullDnsPolicy policy)
    {lock(_gate) {if(Reason=="Active" && Devices.Any(id=>policy.Devices.Count(d=>d.DeviceId==id)!=1))Reason="Approved registration missing or ambiguous";}}
}
