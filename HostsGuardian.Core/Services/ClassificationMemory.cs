using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
/// <summary>64 session observation keys; 24-hour summary cap. No physical identity or raw-packet persistence.</summary>
public sealed class ClassificationMemory
{
    private readonly Dictionary<Guid,(InferredClassificationMemory Value,string Signature)> _items=new();
    public int Count=>_items.Count;
    public void Remember(Guid observation,InferredClassificationMemory summary)
    {
        if(_items.TryGetValue(observation,out var prior) && prior.Value.Classification.AssessedAtUtc>=summary.Classification.AssessedAtUtc)return;
        if(!_items.ContainsKey(observation) && _items.Count>=64)_items.Remove(_items.MinBy(p=>p.Value.Value.RetainUntilUtc).Key);
        _items[observation]=(summary,"");
    }
    public InferredClassificationMemory? Update(Guid observation,DeviceClassification current,DateTimeOffset now)
    {
        foreach(var key in _items.Where(p=>p.Value.Value.RetainUntilUtc<=now).Select(p=>p.Key).ToArray())_items.Remove(key);
        if(current.DeviceType!="Unknown" && current.Confidence is "Medium" or "High" && !current.ConflictingEvidence)
        {
            var relevant=current.Evidence.Where(e=>e.Provider!="Neighbour/OUI").ToArray();
            var signature=string.Join("|",relevant.Select(e=>$"{e.Provider}:{e.Kind}:{e.Value}:{e.ObservedAtUtc:O}").Order());
            signature=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(current.DeviceType+":"+current.Confidence+":"+signature)));
            if(!_items.TryGetValue(observation,out var previous) || previous.Signature!=signature && !(previous.Signature=="" && current.DeviceType==previous.Value.Classification.DeviceType && current.Confidence==previous.Value.Classification.Confidence && relevant.All(e=>e.ObservedAtUtc<=previous.Value.Classification.AssessedAtUtc)))
            {
                if(!_items.ContainsKey(observation) && _items.Count>=64)_items.Remove(_items.MinBy(p=>p.Value.Value.RetainUntilUtc).Key);
                var freshUntil=(relevant.Length==0?current.AssessedAtUtc:relevant.Min(e=>e.ObservedAtUtc)).AddMinutes(5);
                var summary=current with {Evidence=[],EvidenceFreshUntilUtc=freshUntil};
                var provenance=relevant.Select(e=>e.Provider+" · "+e.Kind+(e.Kind is "Service" or "DeviceRole"?": "+e.Value:"")).Distinct().Take(4).ToArray();
                _items[observation]=(new(summary,provenance,now.AddHours(24)),signature);
            }
        }
        return _items.TryGetValue(observation,out var entry)?entry.Value:null;
    }
}
