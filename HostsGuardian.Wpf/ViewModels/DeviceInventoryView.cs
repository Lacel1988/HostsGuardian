using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.Wpf.ViewModels;
public static class DeviceInventoryView
{
    public static DeviceVm[] Merge(IEnumerable<DeviceVm> observations,FullDnsPolicy policy,IEnumerable<DeviceVm>? previous=null)
    {
        var rows=observations.ToList();
        var projected=DeviceIdentityProjection.Apply(rows.Where(r=>r.LanObservation!=null).Select(r=>r.LanObservation!).ToArray(),policy);
        foreach(var row in rows)
        {
            var orphan=row.ClearOrphanedRegistration(policy);
            if(!orphan && row.LanObservation is {} observation)
            {
                var evidence=projected.First(d=>d.ObservationDeviceId==observation.ObservationDeviceId);
                if(row.DeviceId is Guid associated && evidence.Identity?.DeviceId!=associated)row.ClearOrphanedRegistration(FullDnsPolicy.Empty);
                row.LanObservation=evidence;
            }
            if(row.DeviceId is Guid id && policy.Devices.FirstOrDefault(d=>d.DeviceId==id) is {} member)row.ApplyRegistration(member,policy);
        }
        foreach(var registration in policy.Devices)
        {
            if(rows.Any(d=>d.DeviceId==registration.DeviceId))continue;
            var old=previous?.FirstOrDefault(d=>d.DeviceId==registration.DeviceId);
            var inventoryRow=new DeviceVm(new NetworkDevice{Mac=registration.Mac ?? ""},DeviceIdentityProjection.FriendlyName(registration),false)
            {DeviceId=registration.DeviceId,ConfirmedType=registration.Metadata?.Type ?? "",LastSeenUtc=old?.LanObservation?.LastObservedUtc ?? old?.ObservedAtUtc ?? old?.LastSeenUtc,
             RetainedClassification=old?.LanObservation?.LastReliableClassification ?? old?.RetainedClassification,
             RegisteredGroups=policy.Program?.Groups.Where(g=>g.DeviceIds.Contains(registration.DeviceId)).Select(g=>g.Name).ToArray() ?? []};
            inventoryRow.ApplyRegistration(registration,policy);rows.Add(inventoryRow);
        }
        return rows.OrderBy(d=>d.DeviceId is null).ToArray();
    }
}
