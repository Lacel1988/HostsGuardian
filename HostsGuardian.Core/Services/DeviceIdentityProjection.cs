using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

public static class DeviceIdentityProjection
{
    public static string FriendlyName(DeviceRegistration registration) =>
        string.IsNullOrWhiteSpace(registration.Metadata?.Alias) ? registration.Name : registration.Metadata.Alias;

    public static DeviceRegistration Rename(DeviceRegistration registration, string name) => registration with
    {
        Name = name.Trim(), Metadata = registration.Metadata is {} metadata ? metadata with { Alias = name.Trim() } : null
    };
    public static DeviceRegistration ConfirmType(DeviceRegistration registration,string type)
    {
        var canonical=type==""?"":DeviceTypes.Find(type)?.Id ?? throw new ArgumentException("Unsupported device type");
        var metadata=registration.Metadata ?? new DeviceMetadata(FriendlyName(registration),"","","");
        return registration with {Metadata=metadata with {Type=canonical}};
    }

    public static LanDeviceObservation[] Apply(LanDeviceObservation[] observations, FullDnsPolicy policy)
    {
        return observations.Select(observation =>
        {
            var macs = observation.Evidence.Select(e => DevicePolicyIdentity.NormalizeMac(e.Mac)).Where(m => m != "").Distinct().ToArray();
            var hostnames = observation.Evidence.Select(e => e.Hostname).Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var privateMac = observation.Evidence.Any(e => e.PrivateMacPossible);
            var candidates = policy.Devices.Where(d => macs.Contains(DevicePolicyIdentity.NormalizeMac(d.Mac))).ToArray();
            // A registration owns its metadata. MAC provides current, explicit association evidence,
            // never universal physical continuity. IP alone is deliberately not consulted.
            var registration = RegisteredMacCorrelation.Find(policy,macs,
                macs.Length==1 ? observations.Count(o=>o.Evidence.Any(e=>DevicePolicyIdentity.NormalizeMac(e.Mac)==macs[0])) : 0,
                observation.EvidenceOmitted==0);
            var unique=registration!=null;
            var conflict = candidates.Length > 0 && !unique;
            var identity = new DeviceIdentityPresentation(registration?.DeviceId, registration == null ? "" : FriendlyName(registration),
                hostnames.Length == 1 ? hostnames[0] : "", registration != null ? "Registered" : conflict ? "Ambiguous" : "Provisional",
                registration != null ? "USER-CONFIRMED" : "UNKNOWN", registration != null ?
                "User-authored control-plane registration; unique current MAC evidence. Physical continuity and DNS binding not proven." :
                conflict ? "Conflicting or incomplete registration evidence; association withheld." : "No unambiguous user registration; network observation only.")
            {
                PrivateMacPossible = privateMac, DeviceType = registration?.Metadata?.Type ?? "",
                Groups = registration == null ? [] : (policy.Program?.Groups.Where(g => g.DeviceIds.Contains(registration.DeviceId)).Select(g => g.Name).ToArray() ?? [])
            };
            return observation with { Identity = identity };
        }).ToArray();
    }
}
