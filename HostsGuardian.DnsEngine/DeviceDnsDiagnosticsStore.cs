using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

/// <summary>64 sources, 10-minute aggregate buckets, memory only. Unknown addresses never become stable DeviceIds.</summary>
public sealed class DeviceDnsDiagnosticsStore
{
    public const int WindowSeconds = 600, MaximumSources = 64;
    private sealed class Row
    {
        public string TrackingId = Guid.NewGuid().ToString("N");
        public Guid? DeviceId; public string State="Unknown", Address="";
        public DateTimeOffset First, Last; public DateTimeOffset? LastDns;
        public long Received;
        public readonly Dictionary<long,long[]> Buckets = new();
    }
    private readonly object _gate=new();
    private readonly Dictionary<string,Row> _rows=new();
    private long _evicted;
    private static void Increment(long[] counts,int index) { if(counts[index]<long.MaxValue) counts[index]++; }
    private void Purge(DateTimeOffset now)
    {
        foreach(var key in _rows.Where(p=>p.Value.Last<now.AddSeconds(-WindowSeconds)).Select(p=>p.Key).ToArray()) _rows.Remove(key);
        var cutoff=now.AddSeconds(-WindowSeconds).ToUnixTimeSeconds()/10;
        foreach(var row in _rows.Values) foreach(var bucket in row.Buckets.Keys.Where(t=>t<cutoff).ToArray()) row.Buckets.Remove(bucket);
    }
    public string Record(DnsRequestContext context, Guid? device, string state, string kind, DateTimeOffset now)
    {
        var address=System.Net.IPAddress.TryParse(context.SourceAddress,out var parsed)?parsed.ToString():"";
        // Scope is internal correlation evidence, never exposed as a network name.
        var key=device is {} id ? "id:"+id : "address:"+address+"|"+context.NetworkScope;
        lock(_gate)
        {
            Purge(now);
            if(!_rows.TryGetValue(key,out var row))
            {
                if(_rows.Count==MaximumSources) { _rows.Remove(_rows.MinBy(p=>p.Value.Last).Key); _evicted++; }
                _rows[key]=row=new() {DeviceId=device,First=now,Last=now};
            }
            row.State=state; row.Address=address; if(now>row.Last) row.Last=now;
            var bucket=now.ToUnixTimeSeconds()/10;
            if(!row.Buckets.TryGetValue(bucket,out var counts)) row.Buckets[bucket]=counts=new long[9];
            if(kind=="Received") { if(row.Received<long.MaxValue) row.Received++; if(row.LastDns==null || now>row.LastDns) row.LastDns=now; Increment(counts,0); }
            else if(kind=="ConnectionRejected") Increment(counts,8);
            return row.TrackingId;
        }
    }
    public void Outcome(string key,string outcome,DateTimeOffset now)
    {
        lock(_gate)
        {
            var row=_rows.Values.FirstOrDefault(r=>r.TrackingId==key);
            if(row==null) return; // Evicted evidence stays unavailable, never reassigned.
            var bucket=now.ToUnixTimeSeconds()/10;
            if(!row.Buckets.TryGetValue(bucket,out var counts)) row.Buckets[bucket]=counts=new long[9];
            switch(outcome)
            {
                case "Allowed":Increment(counts,1);break;
                case "Blocked":Increment(counts,2);break;
                case "Servfail":Increment(counts,3);Increment(counts,4);break;
                case "Failed":Increment(counts,3);break;
                case "Rejected":Increment(counts,5);break;
                case "Dropped":Increment(counts,5);Increment(counts,6);break;
                case "Cancelled":Increment(counts,7);break;
            }
        }
    }
    public DeviceDiagnosticsSnapshot Snapshot(FullDnsPolicy policy,string instance,long? revision,DateTimeOffset now)
    {
        // Passive OS/provider I/O must never hold the DNS counter hot-path lock.
        var network=HostsGuardian.Core.Services.PassiveIdentityEvidence.Read();
        lock(_gate)
        {
            Purge(now);
            var devices=_rows.Values.OrderByDescending(r=>r.Received).Select(row=>
            {
                var registration=policy.Devices.FirstOrDefault(d=>d.DeviceId==row.DeviceId);
                var alias=registration?.Metadata?.Alias;
                var name=!string.IsNullOrWhiteSpace(alias)?alias:registration?.Name;
                var evidence=registration!=null?"USER-CONFIRMED":"UNKNOWN";
                var candidates=network.Where(n=>n.Address==row.Address).ToArray();
                var observed=candidates.Length==1?candidates[0]:null;
                if(string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(observed?.Hostname)) { name=observed.Hostname; evidence="OBSERVED"; }
                if(string.IsNullOrWhiteSpace(name)) name="Unknown device";
                var totals=new long[9];
                foreach(var counts in row.Buckets.Values) for(var i=0;i<9;i++) totals[i]=counts[i]>long.MaxValue-totals[i]?long.MaxValue:totals[i]+counts[i];
                return new DeviceDnsDiagnostic(row.TrackingId,row.DeviceId,row.State,name!,evidence,row.Address,row.First,row.Last,
                    row.LastDns,row.Received,new(totals[0],totals[1],totals[2],totals[3],totals[4],totals[5],totals[6],totals[7],totals[8])) {NetworkEvidence=observed,DeviceType=registration?.Metadata?.Type ?? ""};
            }).ToArray();
            var lan=HostsGuardian.Core.Services.LanObservationStore.Shared.Observe(network,now);
            return new(1,instance,now,revision,WindowSeconds,MaximumSources,_evicted,devices)
                {LanDevices=HostsGuardian.Core.Services.DeviceIdentityProjection.Apply(HostsGuardian.Core.Services.LanObservationStore.Correlate(lan,devices),policy),DiscoveryStatus=HostsGuardian.Core.Services.LanDiscoveryRefresh.LastReport+" "+HostsGuardian.Core.Services.FingerprintDiscovery.LastReport};
        }
    }
}
