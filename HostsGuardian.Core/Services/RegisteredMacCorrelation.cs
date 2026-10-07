using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

/// <summary>Registration association only; never physical continuity or IP-only identity.</summary>
public static class RegisteredMacCorrelation
{
    public static DeviceRegistration? Find(FullDnsPolicy policy, string[] macs, int observationCount, bool complete)
    {
        var normalized=macs.Select(DevicePolicyIdentity.NormalizeMac).Where(m=>m!="").Distinct().ToArray();
        if(!complete || normalized.Length!=1 || observationCount!=1)return null;
        var candidates=policy.Devices.Where(d=>DevicePolicyIdentity.NormalizeMac(d.Mac)==normalized[0]).ToArray();
        return candidates.Length==1 ? candidates[0] : null;
    }
}
public sealed record BindingEvidenceRead(DateTimeOffset ReadAtUtc, bool Complete, NetworkIdentityEvidence[] Evidence);
