using HostsGuardian.Core.Models;
using System.Net;
namespace HostsGuardian.Core.Services;

/// <summary>Bounded session correlation, independently of DNS. No policy bindings or identity writes.</summary>
public sealed class LanObservationStore
{
    public static LanObservationStore Shared { get; } = new();
    private readonly ClassificationMemory _classificationMemory=new();
    private readonly Func<DateTimeOffset,FingerprintEvidence[]> _fingerprints;
    public LanObservationStore(Func<DateTimeOffset,FingerprintEvidence[]>? fingerprints=null) => _fingerprints=fingerprints ?? FingerprintDiscovery.Snapshot;
    private readonly object _gate = new();
    private readonly Dictionary<string, LanDeviceObservation> _devices = new();
    public LanDeviceObservation[] Observe(IEnumerable<NetworkIdentityEvidence> observations, DateTimeOffset now)
    {
        lock (_gate)
        {
            foreach (var key in _devices.Where(p => (p.Value.LastReadAtUtc ?? p.Value.LastObservedUtc) < now.AddMinutes(-10)).Select(p => p.Key).ToArray()) _devices.Remove(key);
            foreach (var evidence in observations.Take(128))
            {
                if (!IPAddress.TryParse(evidence.Address, out var ip) || IPAddress.IsLoopback(ip) ||
                    (evidence.ReadAtUtc ?? evidence.ObservedAtUtc) < now.AddMinutes(-10) || evidence.ObservedAtUtc > now.AddSeconds(30) ||
                    evidence.NeighborState is "FAILED" or "INCOMPLETE") continue;
                var mac = DevicePolicyIdentity.NormalizeMac(evidence.Mac);
                // Same MAC on the same observed interface is provisional correlation, not physical identity.
                var key = evidence.Interface + "|" + (mac == "" ? "address:" + ip : "mac:" + mac);
                if (!_devices.TryGetValue(key, out var device))
                {
                    if (_devices.Count >= 64) _devices.Remove(_devices.MinBy(p => p.Value.LastObservedUtc).Key);
                    device = new(Guid.NewGuid(), "SESSION / PROVISIONAL", "OBSERVED", evidence.ObservedAtUtc, evidence.ObservedAtUtc, []);
                }
                var retained = device.Evidence.Where(e => (e.ReadAtUtc ?? e.ObservedAtUtc) >= now.AddMinutes(-10) &&
                    !(e.Address == evidence.Address && e.Provenance == evidence.Provenance && e.Mac == evidence.Mac && e.Hostname == evidence.Hostname)).ToList();
                retained.Add(evidence);
                _devices[key] = device with { LastReadAtUtc=evidence.ReadAtUtc ?? evidence.ObservedAtUtc, LastObservedUtc = evidence.ObservedAtUtc > device.LastObservedUtc ? evidence.ObservedAtUtc : device.LastObservedUtc,
                    EvidenceOmitted = device.EvidenceOmitted + Math.Max(0,retained.Count-8),
                    Evidence = retained.OrderByDescending(e => e.ObservedAtUtc).Take(8).ToArray() };
            }
            return _devices.Values.OrderByDescending(d => d.LastObservedUtc).Select(d=>d with {Classification=DeviceClassifier.Classify(
                _fingerprints(now).Where(e=>d.EvidenceOmitted==0 && d.Evidence.Any(n=>n.Address==e.Address && n.ObservedAtUtc>=now.AddMinutes(-5)) && _devices.Values.Count(other=>other.Evidence.Any(n=>n.Address==e.Address))==1)
                .Concat(d.Evidence.Where(e=>e.Hostname!="").Select(e=>new FingerprintEvidence(e.Address,"Hostname","Hostname",e.Hostname,e.ObservedAtUtc)))
                .Concat(d.Evidence.Where(e=>e.Mac!="").Select(e=>new FingerprintEvidence(e.Address,"Neighbour/OUI","MAC scope",e.PrivateMacPossible?"Locally administered; vendor unavailable":DeviceDiscoveryService.GuessVendor(e.Mac) is {Length:>0} vendor?"Weak vendor hint: "+vendor:"Globally administered; vendor unavailable",e.ObservedAtUtc))),now)}).Select(d=>d with {LastReliableClassification=_classificationMemory.Update(d.ObservationDeviceId,d.Classification!,now)}).ToArray();
        }
    }
    public static LanDeviceObservation[] Correlate(LanDeviceObservation[] lan, DeviceDnsDiagnostic[] dns)
    {
        return lan.Select(device =>
        {
            var observed = dns.Any(row => device.Evidence.Any(e => e.Address == row.LastObservedAddress) &&
                lan.Count(other => other.Evidence.Any(e => e.Address == row.LastObservedAddress)) == 1 && row.Window.Received > 0);
            var conflict = device.Evidence.Any(e => lan.Count(other => other.Evidence.Any(x => x.Address == e.Address)) > 1);
            return device with { DnsActivity = observed ? "OBSERVED" : "NOT OBSERVED", Coverage = observed ? "PARTIAL" : "UNKNOWN",
                Explanation = conflict ? "Conflicting address evidence; DNS correlation withheld for ambiguous bindings." : observed ?
                    "Engine DNS use observed within the retained interval; exclusive coverage remains unconfirmed." :
                    "LAN presence observed, but no Engine DNS activity correlated. Idle state or an alternate path remain possible; bypass is not proven." };
        }).ToArray();
    }
}
