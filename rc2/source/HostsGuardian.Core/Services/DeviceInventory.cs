using System.Collections.Immutable;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
/// <summary>User-owned registration lifecycle; independent of bounded discovery.</summary>
public static class DeviceInventory
{
    public static FullDnsPolicy Forget(FullDnsPolicy policy,Guid id)
    {
        var program=policy.Program;
        if(program is not null)
        {
            var profiles=program.Profiles.Select(p=>p with {DeviceIds=p.DeviceIds.Where(d=>d!=id).ToImmutableArray()})
                .Where(p=>p.AppliesGlobally || p.DeviceIds.Length+p.GroupIds.Length>0).ToImmutableArray();
            var ids=profiles.Select(p=>p.ProfileId).ToHashSet();
            program=program with {Groups=program.Groups.Select(g=>g with {DeviceIds=g.DeviceIds.Where(d=>d!=id).ToImmutableArray()}).ToImmutableArray(),
                Profiles=profiles,Schedules=program.Schedules.Where(s=>ids.Contains(s.ProfileId)).ToImmutableArray()};
        }
        return PolicyCanonicalization.Canonicalize(policy with {Devices=policy.Devices.Where(d=>d.DeviceId!=id).ToImmutableArray(),
            Overrides=policy.Overrides.Where(o=>o.DeviceId!=id).ToImmutableArray(),Program=program});
    }
}
