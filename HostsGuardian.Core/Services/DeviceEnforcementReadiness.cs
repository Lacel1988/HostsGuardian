using System.Net;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;

public sealed record DeviceEnforcementAssessment(string State, string? Address = null, DateTimeOffset? ExpiresAtUtc = null);

/// <summary>Read-only presentation of current enforcement evidence, separate from inventory and coverage.</summary>
public static class DeviceEnforcementReadiness
{
    public static DeviceEnforcementAssessment Assess(Guid? deviceId, FullDnsPolicy policy, BindingRead? bindings,
        DateTimeOffset? readAtUtc, DateTimeOffset now)
    {
        if (deviceId is null || bindings is null || bindings.Observations.IsDefault || readAtUtc is null ||
            readAtUtc > now || now-readAtUtc >= TimeSpan.FromSeconds(15)) return new("Unknown");
        var registrations=policy.Devices.Where(d=>d.DeviceId==deviceId).ToArray();
        if(registrations.Length!=1)return new(registrations.Length>1?"Conflict":"Unknown");
        var mac=DevicePolicyIdentity.NormalizeMac(registrations[0].Mac);
        if(mac=="")return new("Unknown");
        if(policy.Devices.Count(d=>DevicePolicyIdentity.NormalizeMac(d.Mac)==mac)!=1)return new("Conflict");
        var rows=bindings.Observations.Where(b=>b.DeviceId==deviceId).ToArray();
        var fresh=rows.Where(b=>b.Validated && b.ObservedAtUtc<=now && now<b.ExpiresAtUtc).ToArray();
        if(fresh.Length==0)return new(rows.Any(b=>b.Validated && b.ObservedAtUtc<=now && b.ExpiresAtUtc<=now)?"Stale":"Unknown");
        if(fresh.Any(b=>DevicePolicyIdentity.NormalizeMac(b.MacEvidence)!=mac || b.NetworkScope is not null ||
            string.IsNullOrWhiteSpace(b.Interface) || b.ExpiresAtUtc-b.ObservedAtUtc>TimeSpan.FromSeconds(45) ||
            !IPAddress.TryParse(b.Address,out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork))return new("Conflict");
        if(fresh.Select(b=>b.Address).Distinct().Count()!=1 || fresh.Select(b=>b.Interface).Distinct().Count()!=1)return new("Conflict");
        var address=fresh[0].Address;
        if(bindings.Observations.Any(b=>b.Address==address && b.NetworkScope is null && b.DeviceId!=deviceId &&
            b.Validated && b.ObservedAtUtc<=now && now<b.ExpiresAtUtc))return new("Conflict");
        return new("Verified",address,fresh.Min(b=>b.ExpiresAtUtc));
    }
}
