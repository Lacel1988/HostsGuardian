using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

public static class DeviceClassifier
{
    public static DeviceClassification Classify(IEnumerable<FingerprintEvidence> input,DateTimeOffset now)
    {
        var evidence=input.Where(e=>e.ObservedAtUtc>=now.AddMinutes(-5) && e.ObservedAtUtc<=now.AddSeconds(5)
            && e.Value.Length<=256 && !e.Value.Any(char.IsControl)).DistinctBy(e=>(e.Address,e.Provider,e.Kind,e.Value)).Take(33).ToArray();
        if(evidence.Length>32)return new("Unknown","Unknown","INFERRED","Fingerprint evidence limit exceeded; classification withheld, evidence truncated.",now,evidence.Take(32).ToArray());
        var votes=new List<(string Type,string Provider,bool Strong)>();
        foreach(var e in evidence)
        {
            var value=e.Value.ToLowerInvariant();
            if(e.Provider=="mDNS" && e.Kind=="Service")
            {
                if(value is "_ipp._tcp.local" or "_ipps._tcp.local" or "_printer._tcp.local")votes.Add(("Printer",e.Provider,true));
                // Android-TV/casting services occur on TVs and streaming boxes: capability only.
            }
            if(e.Provider=="SSDP" && e.Kind=="DeviceRole")
            {
                if(value=="urn:schemas-upnp-org:device:printer:1")votes.Add(("Printer",e.Provider,true));
                if(value is "urn:schemas-upnp-org:device:internetgatewaydevice:1" or "urn:schemas-upnp-org:device:wanconnectiondevice:1")votes.Add(("Network",e.Provider,true));
            }
            if(e.Kind is "Hostname" or "Advertised friendlyName")
            {
                var hint=DeviceTypes.Assess("",[e.Value]);
                if(hint.Type.Id!="Unknown")votes.Add((hint.Type.Id,e.Provider,false));
            }
        }
        var categories=votes.Select(v=>v.Type).Distinct().ToArray();
        if(categories.Length!=1)return new("Unknown","Unknown","INFERRED",categories.Length>1?
            "Conflicting classification evidence retained; no category selected.":
            "No class-specific evidence; generic media capabilities and vendor alone do not establish a device class.",now,evidence){ConflictingEvidence=categories.Length>1};
        var sources=votes.Where(v=>v.Strong).Select(v=>v.Provider).Distinct().Count();
        var mediaSupport=categories[0] is "TV" or "Streaming" or "Speaker" && evidence.Any(e=>
            e.Provider=="SSDP" && e.Kind=="DeviceRole" && e.Value.Equals("urn:schemas-upnp-org:device:MediaRenderer:1",StringComparison.OrdinalIgnoreCase));
        if(sources==0 && mediaSupport)return new(categories[0],"Medium","INFERRED","Advertised category name agrees with media-renderer capability; untrusted claims, not physical identity proof.",now,evidence);
        return new(categories[0],sources>=2?"High":sources==1?"Medium":"Low","INFERRED",
            sources>=2?"Independent protocol roles agree; advertisements are claims, not verified physical identity.":
            sources==1?"Class-specific advertised protocol role; inferred, not user-confirmed.":"Weak observed hostname hint only; device class is uncertain.",now,evidence);
    }
}
