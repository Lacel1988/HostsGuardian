using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.DnsEngine;

/// <summary>Receive-only IPC; background refresh and bounded request-path refresh share publication.</summary>
public sealed class PassiveDnsL2BindingProducer(AddressBindingStore store,Func<FullDnsPolicy> policy,
    Func<BindingEvidenceRead> neighbours,IEndpointValidator validator,Func<DateTimeOffset>? clock=null,
    TimeSpan? maximumEvidenceAge=null)
{
    public const string Method="PassiveDnsL2";
    public static readonly TimeSpan Lifetime=TimeSpan.FromSeconds(10);
    private PassiveDnsL2Read? _lastRead;
    private long _lastReadMonotonic;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    public string State=>Volatile.Read(ref _lastRead) is {Complete:true,Method:Method} read && CaptureValid(read) &&
        Stopwatch.GetElapsedTime(Volatile.Read(ref _lastReadMonotonic))<TimeSpan.FromSeconds(3)?"READY":"UNAVAILABLE";
    public string? CaptureInstance=>Volatile.Read(ref _lastRead)?.CaptureInstance;
    public long InterfaceGeneration=>Volatile.Read(ref _lastRead)?.InterfaceGeneration ?? 0;
    public string Reason=>Volatile.Read(ref _lastRead)?.Reason is {Length:<=160} reason?reason:"Passive evidence unavailable or malformed";
    public async Task RefreshAsync(CancellationToken cancellation)
    {
        await _refreshGate.WaitAsync(cancellation);
        try { await RefreshCoreAsync(cancellation); }
        finally { _refreshGate.Release(); }
    }
    private async Task RefreshCoreAsync(CancellationToken cancellation)
    {
        var id=Guid.NewGuid().ToString("N");
        try
        {
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            var read=await validator.ReadPassiveDnsAsync(id,timeout.Token).WaitAsync(timeout.Token);
            var kernel=neighbours();
            var current=policy();
            var now=clock?.Invoke() ?? DateTimeOffset.UtcNow;
            Volatile.Write(ref _lastReadMonotonic,Stopwatch.GetTimestamp());
            Volatile.Write(ref _lastRead,read is {RequestId:var received,Method:Method} && received==id && read.ReadAtUtc<=now && now-read.ReadAtUtc<TimeSpan.FromSeconds(3)?read:null);
            var rows=Build(current,kernel,read,id,now,maximumEvidenceAge);
            cancellation.ThrowIfCancellationRequested();
            // Wall-clock rollback cannot prolong an already published packet claim.
            var remaining=rows.Length==0?TimeSpan.Zero:rows.Min(r=>r.ExpiresAtUtc-now);
            var started=Stopwatch.GetTimestamp();
            store.PublishObserved(rows,()=>Stopwatch.GetElapsedTime(started)<remaining);
        }
        catch { Volatile.Write(ref _lastRead,null);store.PublishObserved([]); } // DNS remains independent; helper failure creates no binding.
    }
    private static bool CaptureValid(PassiveDnsL2Read read) => read.CaptureInstance is null ||
        (read.CaptureInstance.Length==32 && read.CaptureInstance.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
         read.InterfaceGeneration>0 && read.CaptureState=="READY");
    public static ImmutableArray<AddressBindingObservation> Build(FullDnsPolicy policy,BindingEvidenceRead neighbours,
        PassiveDnsL2Read? read,string requestId,DateTimeOffset now,TimeSpan? maximumEvidenceAge=null)
    {
        var limit=maximumEvidenceAge ?? Lifetime;
        if(limit<TimeSpan.FromSeconds(1) || limit>ValidatedBindingProducer.MaximumEvidenceAge)return [];
        if(limit>Lifetime)limit=Lifetime;
        if(read is null || !read.Complete || read.Method!=Method || read.RequestId!=requestId || read.Evidence is null ||
            read.Evidence.Length>64 || read.ReadAtUtc>now || now-read.ReadAtUtc>=TimeSpan.FromSeconds(3) ||
            !neighbours.Complete || neighbours.ReadAtUtc>now || now-neighbours.ReadAtUtc>=TimeSpan.FromSeconds(3) || neighbours.Evidence.Length>=64)return [];
        if(read.Evidence.Any(e=>e is null || e.ObservedAtUtc>read.ReadAtUtc || e.ObservedAtUtc>now ||
            e.ExpiresAtUtc<=e.ObservedAtUtc || e.ExpiresAtUtc>e.ObservedAtUtc+Lifetime))return [];
        if(!CaptureValid(read))return [];
        var result=ImmutableArray.CreateBuilder<AddressBindingObservation>();
        foreach(var group in read.Evidence.GroupBy(e=>e.Address))
        {
            // Multiple claims remain present in the helper's bounded TTL cache; no last-writer-wins.
            if(group.Count()!=1)continue;
            var claim=group.Single();var mac=DevicePolicyIdentity.NormalizeMac(claim.Mac);
            if(!IPAddress.TryParse(claim.Address,out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork ||
                ip.ToString()!=claim.Address || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.GetAddressBytes()[0]>=224 ||
                mac!=claim.Mac || mac.Length!=17 || mac=="00:00:00:00:00:00" ||
                !byte.TryParse(mac[..2],System.Globalization.NumberStyles.HexNumber,null,out var first) || (first&1)!=0 ||
                string.IsNullOrEmpty(claim.Interface) || claim.Interface.Length>15 || !claim.Interface.All(c=>char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or ':' or '-') || now-claim.ObservedAtUtc>=limit || claim.ExpiresAtUtc<=now)continue;
            if(read.Evidence.Count(e=>e.Mac==mac)!=1)continue;
            // Cached neighbour data only corroborates interface/MAC and vetoes conflicts.
            // Its NUD state/confirmation age NEVER creates or refreshes this binding.
            var kernel=neighbours.Evidence.Where(e=>e.Address==claim.Address).ToArray();
            if(kernel.Length!=1 || kernel[0].Interface!=claim.Interface || kernel[0].Confidence!="OBSERVED" ||
                DevicePolicyIdentity.NormalizeMac(kernel[0].Mac)!=mac ||
                kernel[0].NeighborState.Split('/').Any(s=>s is "FAILED" or "INCOMPLETE" or "Unknown") ||
                kernel[0].ObservedAtUtc>now || neighbours.Evidence.Count(e=>DevicePolicyIdentity.NormalizeMac(e.Mac)==mac &&
                    IPAddress.TryParse(e.Address,out var claimed) && claimed.AddressFamily==AddressFamily.InterNetwork)!=1 ||
                neighbours.Evidence.Where(e=>DevicePolicyIdentity.NormalizeMac(e.Mac)==mac).Select(e=>e.Interface).Distinct().Count()!=1)continue;
            var registration=RegisteredMacCorrelation.Find(policy,[mac],1,true);
            if(registration is null || registration.DeviceId==Guid.Empty)continue;
            var expiry=claim.ExpiresAtUtc<claim.ObservedAtUtc+limit?claim.ExpiresAtUtc:claim.ObservedAtUtc+limit;
            result.Add(new(claim.Address,null,registration.DeviceId,
                "OBSERVED: incoming Ethernet IPv4 DNS; unique registered MAC/interface; unauthenticated L2 claim",
                claim.ObservedAtUtc,expiry,true)
                {MacEvidence=mac,Interface=claim.Interface,ValidationMethod=Method,ValidatedAtUtc=claim.ObservedAtUtc});
        }
        return result.ToImmutable();
    }
}
