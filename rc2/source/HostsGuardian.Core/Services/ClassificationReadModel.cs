using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
/// <summary>Bounded readback reconciliation, not registration or a second discovery pipeline.</summary>
public sealed class ClassificationReadModel
{
 private readonly object _gate=new();
 private readonly ClassificationMemory _memory=new();
 public LanDeviceObservation Apply(LanDeviceObservation row,DateTimeOffset now)
 {
  lock(_gate)
  {
   var current=row.Classification;
   if(row.LastReliableClassification is {} retained && retained.RetainUntilUtc>now && retained.RetainUntilUtc<=now.AddHours(24)
      && retained.Classification.AssessedAtUtc<=now.AddSeconds(5) && retained.Classification.Confidence is "Medium" or "High"
      && retained.Classification.DeviceType!="Unknown" && DeviceTypes.Find(retained.Classification.DeviceType) is not null
      && retained.Classification.Source=="INFERRED" && !retained.Classification.ConflictingEvidence
      && retained.Classification.Reason is {Length:<=256} && !retained.Classification.Reason.Any(char.IsControl)
      && retained.Classification.Evidence is {Length:0} && retained.Provenance is {Length:<=4}
      && retained.Provenance.All(p=>p is {Length:<=256} && !p.Any(char.IsControl)))_memory.Remember(row.ObservationDeviceId,retained);
   var valid=current is not null && current.Source=="INFERRED" && current.AssessedAtUtc>=now.AddMinutes(-5) && current.AssessedAtUtc<=now.AddSeconds(5)
      && current.Reason is {Length:<=256} && !current.Reason.Any(char.IsControl)
      && DeviceTypes.Find(current.DeviceType) is not null && current.Evidence is {Length:<=32}
      && current.Evidence.All(e=>e is not null && e.Provider is not null && e.Kind is not null && e.Value is {Length:<=256} && !e.Value.Any(char.IsControl));
   var summary=_memory.Update(row.ObservationDeviceId,valid?current!:new("Unknown","Unknown","INFERRED","No current supported evidence",now,[]),now);
   return row with {LastReliableClassification=summary};
  }
 }
}
