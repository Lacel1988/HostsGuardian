using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.DnsEngine;

/// <summary>Background-only evidence producer. DNS workers never perform network discovery or shell I/O.</summary>
public sealed class ValidatedBindingProducer(AddressBindingStore store,Func<FullDnsPolicy> policy,
    Func<BindingEvidenceRead> evidence,Func<DateTimeOffset>? clock=null)
{
    public static readonly TimeSpan MaximumEvidenceAge=TimeSpan.FromSeconds(15);
    public void Refresh()
    {
        BindingEvidenceRead read;
        try { read=evidence(); } catch { read=new(default,false,[]); }
        var now=clock?.Invoke() ?? DateTimeOffset.UtcNow;
        var currentPolicy=policy();
        var candidate=Build(currentPolicy,read,now);
        store.PublishObserved(candidate);
    }
    public async Task RunAsync(CancellationToken token)
    {
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(2));
        try { do { Refresh(); } while(await timer.WaitForNextTickAsync(token)); }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { }
        finally { store.PublishObserved([]); }
    }
    public static ImmutableArray<AddressBindingObservation> Build(FullDnsPolicy policy,BindingEvidenceRead read,DateTimeOffset now)
    {
        if(!read.Complete || read.ReadAtUtc>now || now-read.ReadAtUtc>=MaximumEvidenceAge || read.Evidence.Length>=64)return [];
        var result=ImmutableArray.CreateBuilder<AddressBindingObservation>();
        foreach(var group in read.Evidence.GroupBy(e=>e.Address).OrderBy(g=>g.Key,StringComparer.Ordinal))
        {
            if(!IPAddress.TryParse(group.Key,out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork || IPAddress.IsLoopback(ip) ||
                ip.Equals(IPAddress.Any) || ip.GetAddressBytes()[0]>=224)continue;
            var entries=group.ToArray();var macs=entries.Select(e=>DevicePolicyIdentity.NormalizeMac(e.Mac)).Distinct().ToArray();
            if(entries.Any(e=>e.ConfirmedAtUtc is null || e.ConfirmedAtUtc>now || now-e.ConfirmedAtUtc.Value>=MaximumEvidenceAge || e.NeighborState!="REACHABLE" || e.Confidence!="OBSERVED" || e.Interface=="" || e.ObservedAtUtc>now) || entries.Select(e=>e.Interface).Distinct().Count()!=1 || macs.Length!=1 ||
                macs[0]=="" || !byte.TryParse(macs[0][..2],System.Globalization.NumberStyles.HexNumber,null,out var first) || (first&1)!=0)continue;
            // A repeated MAC across interfaces cannot establish the null-scope DNS namespace safely.
            if(read.Evidence.Where(e=>DevicePolicyIdentity.NormalizeMac(e.Mac)==macs[0]).Select(e=>e.Interface).Distinct().Count()!=1)continue;
            var registration=RegisteredMacCorrelation.Find(policy,macs,1,true);if(registration==null)continue;
            var observed=entries.Min(e=>e.ConfirmedAtUtc!.Value);var expires=observed+MaximumEvidenceAge;
            result.Add(new(ip.ToString(),null,registration.DeviceId,"OBSERVED: kernel neighbour REACHABLE; unique registered MAC; bounded IPv4 evidence",observed,expires,true)
                {MacEvidence=macs[0],Interface=entries[0].Interface});
        }
        return result.ToImmutable();
    }
}
