using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace DesignPrototype.Engine;

public sealed record LiveConfiguration(string Origin,string EnrolledCertificate,string CredentialId,int PollSeconds=20)
{
    public static LiveConfiguration Load(string path)
    {
        var bytes=File.ReadAllBytes(path);if(bytes.Length>32768)throw new ArgumentException("Configuration too large");
        var c=JsonSerializer.Deserialize<LiveConfiguration>(bytes,new JsonSerializerOptions{UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow})??throw new ArgumentException();
        ValidateOrigin(c.Origin);if(!Guid.TryParseExact(c.CredentialId,"N",out _)||c.PollSeconds is <5 or >120)throw new ArgumentException();
        using var cert=new X509Certificate2(Convert.FromBase64String(c.EnrolledCertificate));if(cert.HasPrivateKey)throw new ArgumentException();return c;
    }
    public static Uri ValidateOrigin(string value)
    {
        if(!Uri.TryCreate(value,UriKind.Absolute,out var u)||u.Scheme!="https"||u.UserInfo!=""||u.AbsolutePath!="/"||u.Query!=""||u.Fragment!=""||!IPAddress.TryParse(u.Host.Trim('[',']'),out var ip))throw new ArgumentException("Explicit HTTPS IP origin required");
        var b=ip.GetAddressBytes();bool local=IPAddress.IsLoopback(ip)||(b.Length==4&&(b[0]==10||b[0]==192&&b[1]==168||b[0]==172&&b[1]>=16&&b[1]<=31))||ip.IsIPv6UniqueLocal;
        if(!local)throw new ArgumentException("Private or loopback origin required");return u;
    }
}
public enum DataState { Fresh, Stale, Unknown, Unavailable }
public enum ReadError { None, Unreachable, Timeout, Cancelled, Tls, Authentication, Forbidden, Server, Unsupported, InvalidJson, Schema, Oversize, Regressed, Incoherent }
public sealed record EvidenceValue(string? Value,string Source,DateTimeOffset ReceivedAt,DateTimeOffset? ObservedAt,DataState Freshness,string Quality,string Proof);
public sealed record EndpointRead(string Path,JsonElement? Value,DateTimeOffset ReceivedAt,DateTimeOffset? ObservedAt,ReadError Error,DataState Freshness)
{
    public bool Usable=>Value is not null&&Error==ReadError.None&&Freshness==DataState.Fresh;
}
public sealed record EngineSnapshot(long Sequence,DateTimeOffset ReceivedAt,IReadOnlyDictionary<string,EndpointRead> Reads)
{
    public EndpointRead? Get(string path)=>Reads.GetValueOrDefault(path);
    public string? Instance=>Json.S(Get("/dns/status")?.Value,"instanceId");
}
public static class Json
{
    public static JsonElement? P(JsonElement? value,string name)=>value is {ValueKind:JsonValueKind.Object} v&&v.TryGetProperty(name,out var p)?p:null;
    public static string? S(JsonElement? value,string name)=>P(value,name) is {ValueKind:JsonValueKind.String} p&&p.GetString() is {} text&&!string.IsNullOrWhiteSpace(text)?Clean(text):null;
    public static long? N(JsonElement? value,string name)=>P(value,name) is {ValueKind:JsonValueKind.Number} p&&p.TryGetInt64(out var n)?n:null;
    public static double? D(JsonElement? value,string name)=>P(value,name) is {ValueKind:JsonValueKind.Number} p&&p.TryGetDouble(out var n)&&double.IsFinite(n)?n:null;
    public static bool? B(JsonElement? value,string name)=>P(value,name) is {ValueKind:JsonValueKind.True}?true:P(value,name) is {ValueKind:JsonValueKind.False}?false:null;
    public static DateTimeOffset? T(JsonElement? value,string name)=>S(value,name) is {} s&&DateTimeOffset.TryParse(s,System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.RoundtripKind,out var d)?d:null;
    public static JsonElement[] A(JsonElement? value,string? name=null){var a=name==null?value:P(value,name);return a is {ValueKind:JsonValueKind.Array} p?p.EnumerateArray().Take(10001).ToArray():[];}
    public static string? Clean(string? value)=>value==null?null:new(value.Where(c=>!char.IsControl(c)).Take(512).ToArray());
}
public sealed class EngineReader:IDisposable
{
    public static IReadOnlyList<string> Paths{get;}=Array.AsReadOnly(new[]{"/dns/status","/v2/capabilities","/v2/policy","/v2/bindings","/v2/discovery","/v2/diagnostics","/v2/dns-observations","/v3/activity","/v2/operational-events?after=0"});
    readonly HttpClient http;readonly Uri origin;readonly Func<string?> credential;readonly Func<string?>? session;readonly TimeSpan timeout;
    public long Requests{get;private set;}public long Bytes{get;private set;}long sequence;
    public EngineReader(string url,string certificate,Func<string?> readCredential,TimeSpan? deadline=null,HttpMessageHandler? testHandler=null,Func<string?>? session=null)
    {
        origin=LiveConfiguration.ValidateOrigin(url);credential=readCredential;this.session=session;timeout=deadline??TimeSpan.FromSeconds(8);
        http=new HttpClient(testHandler??new HttpClientHandler{AllowAutoRedirect=false,UseProxy=false,UseCookies=false,ServerCertificateCustomValidationCallback=(_,cert,_,errors)=>ManagementSecurity.ValidateCertificate(cert,certificate,errors)}){Timeout=Timeout.InfiniteTimeSpan};
    }
    public async Task<EndpointRead> ReadAsync(string path,CancellationToken cancellation)
    {
        if(!Paths.Contains(path,StringComparer.Ordinal))throw new InvalidOperationException("GET path not allowed");
        var now=DateTimeOffset.UtcNow;using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(timeout);
        try
        {
            var token=credential();if(ManagementSecurity.ParseToken(token)==null)return Fail(ReadError.Authentication);
            using var req=new HttpRequestMessage(HttpMethod.Get,new Uri(origin,path));req.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            if(session!=null){var proof=session();if(ManagementSecurity.ParseToken(proof)==null)return Fail(ReadError.Authentication);req.Headers.Add("X-HostsGuardian-Session",proof);}
            Requests++;using var response=await http.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,deadline.Token).ConfigureAwait(false);
            if(!response.IsSuccessStatusCode)return Fail((int)response.StatusCode switch{401=>ReadError.Authentication,403=>ReadError.Forbidden,404=>ReadError.Unsupported,_=>ReadError.Server});
            if(response.Content.Headers.ContentLength>1048576)return Fail(ReadError.Oversize);
            using var stream=await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);using var body=new MemoryStream();var buffer=new byte[8192];int count;
            while((count=await stream.ReadAsync(buffer,deadline.Token).ConfigureAwait(false))>0){Bytes+=count;if(body.Length+count>1048576)return Fail(ReadError.Oversize);body.Write(buffer,0,count);}
            using var parsed=JsonDocument.Parse(body.ToArray(),new JsonDocumentOptions{MaxDepth=32});var value=parsed.RootElement.Clone();
            if(!Unique(value))return Fail(ReadError.InvalidJson);
            bool valid=path=="/v2/discovery"?value.ValueKind==JsonValueKind.Array: value.ValueKind==JsonValueKind.Object;
            if(path=="/dns/status")valid&=Json.S(value,"instanceId") is {Length:>0}&&Json.S(value,"runtimeState")!=null;
            if(path=="/v2/policy")valid&=Json.P(value,"policy") is {ValueKind:JsonValueKind.Object}&&Json.N(value,"revision")>=0;
            if(path=="/v2/bindings")valid&=Json.P(value,"observations") is {ValueKind:JsonValueKind.Array};
            if(path=="/v2/dns-observations")valid&=Json.P(value,"observations") is {ValueKind:JsonValueKind.Array};
            if(path=="/v3/activity")valid&=Json.P(value,"buckets") is {ValueKind:JsonValueKind.Array};
            if(path=="/v2/diagnostics")valid&=Json.S(value,"instanceId")!=null;
            if(!valid)return Fail(ReadError.Schema);
            var received=DateTimeOffset.UtcNow;var observed=Json.T(value,"snapshotUtc")??Json.T(value,"observedAtUtc");
            var fresh=observed is {} time&&(time>received.AddSeconds(5)||received-time>TimeSpan.FromSeconds(60))?DataState.Stale:DataState.Fresh;
            return new(path,value,received,observed,ReadError.None,fresh);
        }
        catch(OperationCanceledException){return Fail(cancellation.IsCancellationRequested?ReadError.Cancelled:ReadError.Timeout);}
        catch(HttpRequestException ex){return Fail(ex.HttpRequestError==HttpRequestError.SecureConnectionError?ReadError.Tls:ReadError.Unreachable);}
        catch(JsonException){return Fail(ReadError.InvalidJson);}
        catch(IOException){return Fail(ReadError.Unreachable);}
        catch{ return Fail(ReadError.Authentication); }
        EndpointRead Fail(ReadError error)=>new(path,null,DateTimeOffset.UtcNow,null,error,DataState.Unavailable);
    }
    static bool Unique(JsonElement e)
    {
        if(e.ValueKind==JsonValueKind.Object){var names=new HashSet<string>();foreach(var p in e.EnumerateObject())if(!names.Add(p.Name)||!Unique(p.Value))return false;}
        if(e.ValueKind==JsonValueKind.Array){if(e.GetArrayLength()>10000)return false;foreach(var p in e.EnumerateArray())if(!Unique(p))return false;}return true;
    }
    public async Task<EngineSnapshot> FetchAsync(CancellationToken cancellation)
    {
        var reads=new Dictionary<string,EndpointRead>();using var budget=CancellationTokenSource.CreateLinkedTokenSource(cancellation);budget.CancelAfter(TimeSpan.FromSeconds(15));
        foreach(var path in Paths){var r=await ReadAsync(path,budget.Token).ConfigureAwait(false);reads[path]=r;if(path=="/dns/status"&&!r.Usable)break;}
        var status=reads.GetValueOrDefault("/dns/status");
        foreach(var path in new[]{"/v2/policy","/v2/diagnostics","/v2/operational-events?after=0"})
        {
            if(!reads.TryGetValue(path,out var r)||!r.Usable)continue;
            var instance=Json.S(r.Value,"instanceId");bool invalid=instance!=null&&instance!=Json.S(status?.Value,"instanceId");
            if(path=="/v2/policy")invalid|=Json.N(r.Value,"revision")!=Json.N(status?.Value,"policyRevision");
            if(invalid)reads[path]=r with{Value=null,Error=ReadError.Incoherent,Freshness=DataState.Unavailable};
        }
        return new(Interlocked.Increment(ref sequence),DateTimeOffset.UtcNow,reads);
    }
    public void Dispose()=>http.Dispose();
}
public sealed class EnginePoller:IAsyncDisposable
{
    readonly EngineReader reader;readonly Func<EngineSnapshot,Task> publish;readonly CancellationTokenSource lifetime=new();readonly SemaphoreSlim flight=new(1,1);Task? loop;
    public TimeSpan Interval{get;}public int Failures{get;private set;}public long Published{get;private set;}public TimeSpan NextDelay{get;private set;}public bool Stopped=>lifetime.IsCancellationRequested;public bool CircuitOpen{get;private set;}
    public EnginePoller(EngineReader r,Func<EngineSnapshot,Task> callback,TimeSpan interval,bool test=false)
    {reader=r;publish=callback;if(interval<(test?TimeSpan.FromMilliseconds(30):TimeSpan.FromSeconds(5))||interval>TimeSpan.FromSeconds(120))throw new ArgumentException();Interval=interval;}
    public static TimeSpan Delay(TimeSpan interval,int failures,double jitter)=>TimeSpan.FromMilliseconds(Math.Min(120000,interval.TotalMilliseconds*Math.Pow(2,Math.Min(failures,5))*(1+Math.Clamp(jitter,-.1,.1))));
    public void Start(){if(loop!=null||Stopped)throw new InvalidOperationException();loop=Task.Run(Loop);}
    async Task Loop(){try{while(!Stopped&&!CircuitOpen){await PollOnceAsync();if(CircuitOpen)break;NextDelay=Delay(Interval,Failures,(Random.Shared.NextDouble()-.5)*.2);await Task.Delay(NextDelay,lifetime.Token);}}catch(OperationCanceledException)when(Stopped){}}
    public void Resume(){if(!CircuitOpen||Stopped)return;CircuitOpen=false;Failures=0;loop=Task.Run(Loop);}
    public async Task<bool> PollOnceAsync()
    {
        if(Stopped||CircuitOpen||!await flight.WaitAsync(0,lifetime.Token).ConfigureAwait(false))return false;
        try{var snapshot=await reader.FetchAsync(lifetime.Token).ConfigureAwait(false);if(Stopped)return false;Failures=snapshot.Get("/dns/status")?.Usable==true?0:Math.Min(8,Failures+1);CircuitOpen=Failures>=8;await publish(snapshot).ConfigureAwait(false);Published++;return true;}
        finally{flight.Release();}
    }
    public async Task RunExclusiveAsync(Func<CancellationToken,Task> action){await flight.WaitAsync(lifetime.Token).ConfigureAwait(false);try{lifetime.Token.ThrowIfCancellationRequested();await action(lifetime.Token).ConfigureAwait(false);}finally{flight.Release();}}
    public async ValueTask DisposeAsync(){lifetime.Cancel();if(loop!=null)try{await loop.ConfigureAwait(false);}catch(OperationCanceledException){}await flight.WaitAsync().ConfigureAwait(false);flight.Release();reader.Dispose();}
}
