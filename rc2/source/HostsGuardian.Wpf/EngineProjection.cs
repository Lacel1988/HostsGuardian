using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.Json;
namespace DesignPrototype.Engine;

public sealed class EngineRow(string key):INotifyPropertyChanged
{
    public string Key{get;}=key;readonly Dictionary<string,string?> fields=new();public bool Present{get;internal set;}=true;public DateTimeOffset LastReceived{get;internal set;}
    public string this[string name]=>fields.GetValueOrDefault(name)??(Loc.English?"Unknown":"Nem ismert");
    public string? Raw(string name)=>fields.GetValueOrDefault(name);
    public void Update(IReadOnlyDictionary<string,string?> values){bool changed=false;foreach(var (k,v) in values)if(!fields.TryGetValue(k,out var old)||old!=v){fields[k]=v;changed=true;}if(changed)PropertyChanged?.Invoke(this,new(null));}
    public event PropertyChangedEventHandler? PropertyChanged;
}
public enum ProofState { Configured, Applied, Verified, Unknown, Unavailable }
public sealed class EngineProjection
{
    public ObservableCollection<EngineRow> Devices{get;}=[];public ObservableCollection<EngineRow> Events{get;}=[];
    public Dictionary<string,EndpointRead> LastGood{get;}=new();public EngineSnapshot? Latest{get;private set;}public long Accepted{get;private set;}public int Regressions{get;private set;}
    public string? Instance{get;private set;}public DateTimeOffset? LastSuccess{get;private set;}public ReadError ConnectionError=>Latest?.Get("/dns/status")?.Error??ReadError.None;
    public bool Connected=>Fresh("/dns/status");public long? Revision=>Json.N(Value("/dns/status"),"policyRevision");
    public JsonElement? Value(string path)=>LastGood.GetValueOrDefault(path)?.Value;
    public bool Fresh(string path,DateTimeOffset? clock=null)
    {
        if(Latest?.Get("/dns/status")?.Usable!=true||Latest.Get(path)?.Usable!=true||!LastGood.TryGetValue(path,out var r))return false;
        var now=clock??DateTimeOffset.UtcNow;return now-r.ReceivedAt<TimeSpan.FromSeconds(60)&&(r.ObservedAt==null||now-r.ObservedAt<TimeSpan.FromSeconds(60));
    }
    public EvidenceValue Field(string path,string field)
    {
        var r=LastGood.GetValueOrDefault(path);var v=Json.P(r?.Value,field);string? text=v is {ValueKind:JsonValueKind.String} s?Json.Clean(s.GetString()):v is {ValueKind:JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False}?v.ToString():null;
        return new(text,path,r?.ReceivedAt??default,r?.ObservedAt,r==null?DataState.Unavailable:Fresh(path)?DataState.Fresh:DataState.Stale,text==null?"Missing":"EngineReported","Unknown network effect");
    }
    public bool Apply(EngineSnapshot snapshot)
    {
        if(Latest!=null&&(snapshot.Sequence<=Latest.Sequence||snapshot.ReceivedAt<Latest.ReceivedAt)){Regressions++;return false;}
        var newInstance=snapshot.Get("/dns/status")?.Usable==true?snapshot.Instance:null;
        if(newInstance!=null&&Instance!=null&&newInstance!=Instance&&LastGood.GetValueOrDefault("/dns/status")?.ObservedAt is {} previousTime&&snapshot.Get("/dns/status")?.ObservedAt is {} newTime&&newTime<previousTime){Regressions++;return false;}
        if(newInstance!=null&&Instance!=null&&newInstance!=Instance){LastGood.Clear();Devices.Clear();Events.Clear();}
        if(newInstance!=null)Instance=newInstance;
        var reads=new Dictionary<string,EndpointRead>();
        foreach(var (path,r) in snapshot.Reads)
        {
            if(r.Usable&&LastGood.TryGetValue(path,out var prior)&&prior.ObservedAt is {} previous&&r.ObservedAt is {} incoming&&incoming<previous)
            {reads[path]=r with{Error=ReadError.Regressed,Freshness=DataState.Stale,Value=null};Regressions++;continue;}
            reads[path]=r;if(r.Usable)LastGood[path]=r;
        }
        Latest=snapshot with{Reads=reads};Accepted++;
        if(Fresh("/dns/status"))LastSuccess=snapshot.ReceivedAt;
        if(Fresh("/v2/policy")||Fresh("/v2/discovery"))ProjectDevices();
        if(Fresh("/v2/dns-observations")||Fresh("/v2/operational-events?after=0"))ProjectEvents();
        foreach(var row in Devices){row.Update(new Dictionary<string,string?>{["Freshness"]=Fresh("/v2/discovery")&&row.Present?"Current Engine response":"Stale / retained / unknown"});if(!Fresh("/v2/bindings"))row.Update(new Dictionary<string,string?>{["Binding"]="Unavailable / retained"});}
        return true;
    }
    void ProjectDevices()
    {
        var all=new Dictionary<string,Dictionary<string,string?>>();
        if(Fresh("/v2/policy"))foreach(var registration in Json.A(Json.P(Value("/v2/policy"),"policy"),"devices"))
        {
            var id=Json.S(registration,"deviceId");if(string.IsNullOrWhiteSpace(id))continue;
            all["registry:"+id]=new(){["Id"]=id,["Name"]=Json.S(Json.P(registration,"metadata"),"alias")??Json.S(registration,"name"),["Address"]=null,["Seen"]=null,["Identity"]="User registration; physical continuity unknown",["Source"]="/v2/policy",["Presence"]="Not observed in latest response"};
        }
        if(Fresh("/v2/discovery"))foreach(var device in Json.A(Value("/v2/discovery")))
        {
            var identity=Json.P(device,"identity");var registered=Json.S(identity,"deviceId");var observation=Json.S(device,"observationDeviceId");
            var key=registered!=null?"registry:"+registered:observation!=null?"observation:"+observation:null;if(key==null)continue;
            if(!all.TryGetValue(key,out var values))all[key]=values=new(){["Id"]=registered??observation};
            var evidence=Json.A(device,"evidence");values["Name"]=Json.S(identity,"friendlyName")??values.GetValueOrDefault("Name")??Json.S(identity,"observedHostname");
            values["Address"]=string.Join(", ",evidence.Select(x=>Json.S(x,"address")).Where(x=>x!=null).Distinct());if(values["Address"]=="")values["Address"]=null;
            values["Seen"]=Json.S(device,"lastObservedUtc");values["Confidence"]=Json.S(identity,"confidence")??Json.S(device,"confidence");values["Identity"]=registered!=null?Loc.Pick("Regisztrált kapcsolat; fizikai azonosság nem igazolt","Registered association; physical identity unverified"):Loc.Pick("Ideiglenes megfigyelés; fizikai azonosság nem igazolt","Provisional observation; physical identity unverified");
            values["Source"]="/v2/discovery · "+string.Join("; ",evidence.Select(x=>Json.S(x,"provenance")).Where(x=>x!=null).Distinct().Take(2));values["Presence"]="Engine observation; online state unproven";
        }
        foreach(var (key,values) in all)
        {
            values["Binding"]=!Fresh("/v2/bindings")?"Unavailable":Json.A(Value("/v2/bindings"),"observations").Any(x=>Json.S(x,"deviceId")==values.GetValueOrDefault("Id")&&Json.B(x,"validated")==true&&Json.T(x,"expiresAtUtc")>DateTimeOffset.UtcNow)?"Fresh Engine binding; effect unverified":"No fresh binding";
        }
        Merge(Devices,all,512,DateTimeOffset.UtcNow);
    }
    void ProjectEvents()
    {
        var rows=new Dictionary<string,Dictionary<string,string?>>();int n=0;
        foreach(var item in Json.A(Value("/v2/dns-observations"),"observations").Take(4096))
        {
            var context=Json.P(item,"request");var id=Json.S(context,"correlationId")??Json.N(item,"sequence")?.ToString();
            id??=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(item.GetRawText())));
            var revision=Json.N(item,"policyRevision");var device=Json.S(item,"deviceId");
            var identity=Json.S(item,"identityState");bool assigned=device!=null&&identity=="Validated";
            rows[id]=new(){["Time"]=Json.S(context,"receivedAtUtc"),["Domain"]=Json.S(item,"domain"),["Device"]=assigned?device:null,["Decision"]=Json.B(item,"blocked") is {} block?(block?"Block":"Allow"):null,["Result"]=Json.S(item,"responseState"),["Type"]="DNS decision",["Reason"]=Json.S(item,"reason"),["Revision"]=revision?.ToString(),["Proof"]="Engine decision; network effect unverified",["Source"]="/v2/dns-observations",["User"]=null,["Scope"]=null};n++;
        }
        foreach(var item in Json.A(Value("/v2/operational-events?after=0"),"events").Take(256))
        {
            if(Json.N(item,"sequence") is not {} sequence||Json.S(item,"instanceId") is not {} instance)continue;
            rows["operational:"+instance+":"+sequence]=new(){["Time"]=Json.S(item,"occurredAtUtc"),["Domain"]=null,["Device"]=null,["Decision"]=null,["Result"]=Json.S(item,"state"),["Type"]=Json.S(item,"type"),["Reason"]=Json.S(item,"summaryId"),["Proof"]="Engine operational observation; not DNS enforcement",["Source"]="/v2/operational-events?after=0",["User"]=null,["Scope"]=null};
        }
        Merge(Events,rows,4096,DateTimeOffset.UtcNow,false);
    }
    static void Merge(ObservableCollection<EngineRow> target,Dictionary<string,Dictionary<string,string?>> incoming,int cap,DateTimeOffset now,bool retain=true)
    {
        var by=target.ToDictionary(x=>x.Key);
        foreach(var row in target){row.Present=incoming.ContainsKey(row.Key);if(!row.Present&&retain)row.Update(new Dictionary<string,string?>{["Presence"]="Not in latest response; retained observation",["Binding"]="Unknown / retained"});}
        if(!retain)foreach(var old in target.Where(x=>!x.Present).ToArray())target.Remove(old);
        foreach(var (key,values) in incoming.Take(cap))
        {
            if(!by.TryGetValue(key,out var row)){row=new(key);target.Add(row);}row.Present=true;row.LastReceived=now;row.Update(values);
        }
        foreach(var old in target.Where(x=>!x.Present&&now-x.LastReceived>TimeSpan.FromMinutes(10)).ToArray())target.Remove(old);
        while(target.Count>cap)target.Remove(target.Where(x=>!x.Present).OrderBy(x=>x.LastReceived).FirstOrDefault()??target[0]);
    }
    public ProofState PolicyProof
    {
        get
        {
            if(!Fresh("/v2/policy"))return ProofState.Unavailable;
            // Only an actual Engine decision at the current revision evidences application.
            if(Json.B(Value("/dns/status"),"policyLoaded")==true&&Json.B(Value("/dns/status"),"filteringEnabled")==true&&Fresh("/v2/dns-observations")&&Json.A(Value("/v2/dns-observations"),"observations").Any(x=>Json.N(x,"policyRevision")==Revision))return ProofState.Applied;
            return ProofState.Configured;
        }
    }
    public ProofState NetworkProof=>Fresh("/dns/status")?ProofState.Unknown:ProofState.Unavailable;
    public string Receiver=>"Unavailable via current HTTPS API / not independently observed";
}
