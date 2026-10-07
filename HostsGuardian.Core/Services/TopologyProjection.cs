using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

/// <summary>Background evidence projection; never guesses a remote client's access technology.</summary>
public static class TopologyProjection
{
    public static TopologySnapshot Build(FullDnsPolicy policy,LanDeviceObservation[] observations,
        BindingRead bindings,DateTimeOffset now,string engineId="engine",string[]? gateways=null,AccessTopologyEvidence[]? access=null,ResolverDiagnostics[]? resolvers=null)
    {
        var nodes=new List<TopologyNode>();var links=new List<TopologyLink>();
        nodes.Add(new(engineId,"Engine","HostsGuardian Engine",null,"Computer","Observed","Unknown",[],[],"OBSERVED","UNKNOWN","Unknown","Unknown",
            [new("Engine","OBSERVED","Local Engine diagnostic publication; not a remote access claim",now,now,null)]));
        foreach(var registration in policy.Devices.Take(127))
        {
            var matches=observations.Where(o=>o.Identity?.DeviceId==registration.DeviceId).Take(2).ToArray();
            var observation=matches.Length==1?matches[0]:null;
            nodes.Add(Node("registered:"+registration.DeviceId,"Registered",DeviceIdentityProjection.FriendlyName(registration),registration.DeviceId,registration.Metadata?.Type ?? "",observation));
        }
        foreach(var observation in observations.Where(o=>o.Identity?.DeviceId is null && !o.Evidence.Any(e=>e.NeighborState=="LOCAL")).Take(Math.Max(0,128-nodes.Count)))
            nodes.Add(Node("observation:"+observation.ObservationDeviceId,"Provisional",observation.Identity?.ObservedHostname is {Length:>0} name?name:"Unknown device",null,"",observation));
        var omittedNodes=Math.Max(0,policy.Devices.Length-nodes.Count(n=>n.Kind=="Registered"))+
            Math.Max(0,observations.Count(o=>o.Identity?.DeviceId is null && !o.Evidence.Any(e=>e.NeighborState=="LOCAL"))-nodes.Count(n=>n.Kind=="Provisional"));
        var networks=new List<TopologyNetwork>{new("network:unknown","Network membership unknown","UNKNOWN")};
        foreach(var gateway in (gateways ?? []).Where(g=>System.Net.IPAddress.TryParse(g,out var ip) && !System.Net.IPAddress.IsLoopback(ip)).Distinct().Take(8))
        {
            var node=nodes.FirstOrDefault(n=>n.Addresses.Contains(gateway));
            if(node is null && nodes.Count<128){node=new("gateway:"+gateway,"Gateway","Gateway "+gateway,null,"Network","Configured; reachability unknown","Unknown",[gateway],[],"NOT OBSERVED","UNKNOWN","Unknown","Unknown",[]);nodes.Add(node);}
            if(node is not null){if(node.Kind=="Provisional")nodes[nodes.IndexOf(node)]=node with{Kind="Gateway"};links.Add(new("gateway-path:"+gateway,engineId,node.Id,"Configured gateway path","INFERRED","Local OS gateway configuration; not proof of every client's route",now));}
        }
        foreach(var resolver in (resolvers ?? []).Where(r=>System.Net.IPAddress.TryParse(r.Address,out _)).DistinctBy(r=>r.Address).Take(8))
        {
            if(nodes.Count>=128)break;
            var resolverId="resolver:"+resolver.Address;
            nodes.Add(new(resolverId,"Resolver","Upstream DNS "+resolver.Address,null,"Network","Configured; health "+resolver.State,"Unknown",[resolver.Address],[],resolver.Attempts>0?"OBSERVED":"NOT OBSERVED","UNKNOWN","Unknown","Unknown",[]));
            links.Add(new("upstream:"+resolver.Address,engineId,resolverId,"Upstream DNS",resolver.Attempts>0?"OBSERVED":"INFERRED",resolver.Attempts>0?"Engine aggregate upstream attempts; not proof of exclusive client resolver path":"Configured Engine upstream; no observed attempts",null));
        }
        foreach(var group in (access ?? []).Take(128).Where(e=>e.ObservedAtUtc<=now && e.ExpiresAtUtc>now && e.ExpiresAtUtc<=e.ObservedAtUtc.AddMinutes(10) && e.Technology is "Ethernet" or "Wi-Fi" && e.Confidence is "PROVEN" or "OBSERVED" or "INFERRED").GroupBy(e=>e.ObservationId))
        {
            if(group.Select(e=>(e.Technology,e.ParentId,e.NetworkId)).Distinct().Count()!=1)
            {
                var conflictObservation=observations.FirstOrDefault(o=>o.ObservationDeviceId==group.Key);
                var conflictId=conflictObservation?.Identity?.DeviceId is {} conflictDevice?"registered:"+conflictDevice:"observation:"+group.Key;
                var conflictNode=nodes.FirstOrDefault(n=>n.Id==conflictId);
                if(conflictNode is not null)nodes[nodes.IndexOf(conflictNode)]=conflictNode with{Evidence=conflictNode.Evidence.Concat(group.Take(2).Select(e=>new TopologyEvidence(e.Provider,"UNKNOWN","Conflicting access evidence: "+e.Technology+" via "+e.ParentId,e.ObservedAtUtc,null,null))).Take(8).ToArray()};
                continue;
            }
            var observation=observations.FirstOrDefault(o=>o.ObservationDeviceId==group.Key);if(observation is null)continue;
            var id=observation.Identity?.DeviceId is {} device?"registered:"+device:"observation:"+group.Key;
            var node=nodes.FirstOrDefault(n=>n.Id==id);var e=group.First();if(node is null || nodes.Count>=128 || e.ParentId==id || !Safe(e.ParentId,128) || !Safe(e.NetworkId,128) || !Safe(e.NetworkName,128) || !Safe(e.Provider,128) || !Safe(e.Explanation,256))continue;
            nodes[nodes.IndexOf(node)]=node with{Access=e.Technology,NetworkId=e.NetworkId,Evidence=node.Evidence.Append(new(e.Provider,e.Confidence,e.Explanation,e.ObservedAtUtc,null,null)).Take(8).ToArray()};
            if(nodes.All(n=>n.Id!=e.ParentId))nodes.Add(new(e.ParentId,"Infrastructure",e.ParentId,null,"Network","Evidence available","Unknown",[],[],"NOT OBSERVED","UNKNOWN","Unknown","Unknown",[]));
            links.Add(new("access:"+id,id,e.ParentId,e.Technology,e.Confidence,e.Explanation,e.ObservedAtUtc));
            if(networks.All(n=>n.Id!=e.NetworkId))networks.Add(new(e.NetworkId,e.NetworkName,e.Confidence));
        }
        return new(1,now,nodes.ToArray(),links.Take(256).ToArray(),networks.Take(64).ToArray(),
            omittedNodes,Math.Max(0,links.Count-256));

        static bool Safe(string value,int maximum)=>!string.IsNullOrWhiteSpace(value) && value.Length<=maximum && !value.Any(char.IsControl);

        TopologyNode Node(string id,string kind,string name,Guid? device,string type,LanDeviceObservation? observation)
        {
            var evidence=observation?.Evidence ?? [];
            var addresses=evidence.Select(e=>e.Address).Distinct().Take(8).ToArray();
            var macs=evidence.Select(e=>e.Mac).Where(m=>m!="").Distinct().Take(8).ToArray();
            var binding=bindings.Observations.Any(b=>b.Validated && b.ExpiresAtUtc>now && b.ObservedAtUtc<=now && b.DeviceId==device && addresses.Contains(b.Address));
            var dns=observation?.DnsActivity ?? "NOT OBSERVED";
            if(dns=="OBSERVED")links.Add(new("dns:"+id,id,engineId,"DNS activity","OBSERVED","Engine received DNS from uniquely correlated source address; exclusive coverage and identity of every request remain unproven",observation?.LastObservedUtc));
            if(type=="" && observation?.LastReliableClassification is {} inferred && inferred.RetainUntilUtc>now)type=inferred.Classification.DeviceType;
            var proof=evidence.Take(2).Select(e=>new TopologyEvidence(e.Provenance,e.NeighborState=="LOCAL"?"OBSERVED":"OBSERVED",
                "State "+e.NeighborState+" on observing interface "+e.Interface+"; remote Ethernet/Wi-Fi/SSID unknown",e.EvidenceTimeKnown?e.ObservedAtUtc:null,e.ReadAtUtc ?? e.ObservedAtUtc,e.ConfirmedAtUtc)).ToList();
            if(device is not null)proof.Add(new("User registration","USER-CONFIRMED","Persistent identity; no current presence or physical continuity implied",null,null,null));
            return new(id,kind,name,device,type,observation is null?"Not currently correlated":evidence.Any(e=>e.NeighborState is "STALE" or "PROBE" or "DELAY" or "CACHED")?"Cached; online unknown":"Observed; online unknown",
                "Unknown",addresses,macs,dns,observation?.Coverage ?? "UNKNOWN",binding?"Validated":"Unknown / unvalidated",binding?"Device identity available":"Global fallback / identity unvalidated",proof.ToArray());
        }
    }
}
