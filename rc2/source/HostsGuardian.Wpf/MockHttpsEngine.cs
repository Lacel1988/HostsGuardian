using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
namespace DesignPrototype.Engine;

/// <summary>Isolated TLS fixture, bound only to loopback; never proxies or discovers a network.</summary>
public sealed class MockHttpsEngine:IAsyncDisposable
{
    readonly TcpListener listener=new(IPAddress.Loopback,0);readonly CancellationTokenSource stop=new();readonly ConcurrentDictionary<long,Task> clients=new();readonly X509Certificate2 certificate;Task? loop;long clientId;
    public string Token{get;}=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));public string Certificate=>Convert.ToBase64String(certificate.RawData);public string Origin{get;private set;}="";
    public string Scenario{get;set;}="Normal";public int Generation{get;set;}=1;public bool AutoChange{get;set;}=true;public long RequestCount;public long Bytes;public long Writes;public int Active;public int Peak;public int DelayMilliseconds{get;set;}=900;
    public ConcurrentQueue<string> Methods{get;}=new();public string Instance{get;set;}="mock-instance-a";
    public MockHttpsEngine(string certificateCase="valid")
    {
        using var rsa=RSA.Create(2048);var request=new CertificateRequest("CN=HostsGuardian isolated Gate6 mock",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var san=new SubjectAlternativeNameBuilder();san.AddIpAddress(IPAddress.Parse(certificateCase=="wrong-name"?"192.0.2.1":"127.0.0.1"));request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},false));request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        using var made=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-4),DateTimeOffset.UtcNow.AddDays(certificateCase=="expired"?-1:2));certificate=new X509Certificate2(made.Export(X509ContentType.Pfx));
    }
    public bool ReleaseManagement{get;set;}
    public long ReleaseRevision=75;public HostsGuardian.Core.Models.FullDnsPolicy ReleasePolicy=HostsGuardian.Core.Services.PolicyCanonicalization.Canonicalize(new(2,["keep.invalid"],[new(Guid.Parse("10000000-0000-0000-0000-000000000001"),"Labor TV",null,"fixture","explicit")],[]));
    public long ReleaseFailReadbackAfter=long.MaxValue;
    public bool ReleaseConflict,ReleaseFailWrite,ReleaseFailReadback,ReleaseInactive;
    readonly object releaseLock=new();
    static readonly JsonSerializerOptions ReleaseJson=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase,PropertyNameCaseInsensitive=true};
    public void Start(){listener.Start();Origin=$"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";loop=Accept();}
    async Task Accept()
    {
        try{while(!stop.IsCancellationRequested){var tcp=await listener.AcceptTcpClientAsync(stop.Token);var id=Interlocked.Increment(ref clientId);var task=Serve(tcp);clients[id]=task;_ = task.ContinueWith(_=>clients.TryRemove(id,out var ignored),TaskScheduler.Default);}}
        catch(OperationCanceledException){}catch(SocketException)when(stop.IsCancellationRequested){}
    }
    async Task Serve(TcpClient tcp)
    {
        using(tcp)using(var ssl=new SslStream(tcp.GetStream(),false))
        {
            try
            {
                using var budget=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);budget.CancelAfter(TimeSpan.FromSeconds(12));
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13},budget.Token);
                budget.CancelAfter(Timeout.InfiniteTimeSpan);
                using var reader=new StreamReader(ssl,Encoding.ASCII,false,1024,true);
                while(!stop.IsCancellationRequested)
                {
                var first=await reader.ReadLineAsync(budget.Token);if(first==null)return;
                var parts=first.Split(' ');if(parts.Length<2)return;string method=parts[0],path=parts[1];Methods.Enqueue(method+" "+path);Interlocked.Increment(ref RequestCount);if(method!="GET")Interlocked.Increment(ref Writes);
                int length=0;string? auth=null;int total=first.Length;string? line;while(!string.IsNullOrEmpty(line=await reader.ReadLineAsync(budget.Token))){total+=line.Length;if(total>8192)return;if(line.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase))int.TryParse(line[15..].Trim(),out length);if(line.StartsWith("Authorization:",StringComparison.OrdinalIgnoreCase))auth=line[14..].Trim();}
                if(length<0||length>262144)return;var input=new char[length];int got=0;while(got<length){var n=await reader.ReadAsync(input.AsMemory(got,length-got),budget.Token);if(n==0)return;got+=n;}string requestBody=new(input);
                var active=Interlocked.Increment(ref Active);Peak=Math.Max(Peak,active);
                try
                {
                    string scene=Scenario;int status=200;string body;
                    if(scene=="Disconnected")return;
                    if(scene is "Timeout" or "Delayed")await Task.Delay(scene=="Timeout"?10000:DelayMilliseconds,budget.Token);
                    if(method!="GET"&&!(ReleaseManagement&&method=="POST"&&path=="/v2/policy/replace"))status=405;else if(auth!="Bearer "+Token||scene=="401")status=401;else if(scene=="403")status=403;else if(scene=="500")status=500;else if(scene=="503")status=503;
                    if(scene=="Unsupported"&&path!="/dns/status")status=404;
                    if(path=="/dns/status"&&AutoChange&&RequestCount>18)Generation=Math.Max(Generation,2);
                    body=scene=="BadJson"?"{broken":scene=="Missing"&&path=="/dns/status"?"{}":JsonSerializer.Serialize(Payload(path,scene));
                    if(ReleaseManagement&&status==200)
                    {
                        lock(releaseLock)
                        {
                            if(path=="/v2/policy/replace")
                            {
                                var change=JsonSerializer.Deserialize<HostsGuardian.Core.Models.FullPolicyReplace>(requestBody,ReleaseJson);
                                if(ReleaseFailWrite)status=503;
                                else if(ReleaseConflict){ReleaseConflict=false;ReleaseRevision++;ReleasePolicy=HostsGuardian.Core.Services.PolicyCanonicalization.Canonicalize(ReleasePolicy with{GlobalBlockedDomains=ReleasePolicy.GlobalBlockedDomains.Add("concurrent.invalid")});status=409;}
                                else if(change==null||change.ExpectedRevision!=ReleaseRevision||change.ExpectedInstanceId!=Instance)status=409;
                                else{ReleasePolicy=change.Policy;ReleaseRevision++;body=JsonSerializer.Serialize(new{ok=true,revision=ReleaseRevision});}
                            }
                            else if(path=="/v2/policy") {if(ReleaseFailReadback&&Writes>ReleaseFailReadbackAfter)status=503;body=JsonSerializer.Serialize(new HostsGuardian.Core.Models.FullPolicyRead(ReleaseRevision,ReleasePolicy,Instance),ReleaseJson);}
                            else if(path=="/v2/capabilities")body=JsonSerializer.Serialize(new{policySchemaVersion=2,supportedPolicySchemas=new[]{2,3},fullPolicyReadback=true,optimisticConcurrency=true,ipv6DeviceEnforcement=false});
                            else if(path=="/health")body="{\"engine\":\"HostsGuardian.DnsEngine\",\"apiVersion\":1}";
                            else if(path=="/dns/status")body=JsonSerializer.Serialize(new HostsGuardian.Core.Models.DnsServiceStatus{Implementation="HostsGuardian.DnsEngine",InstanceId=Instance,DnsPort=53,ApiPort=new Uri(Origin).Port,RuntimeState="Running",UdpListening=true,TcpListening=true,TcpImplemented=true,UdpState="Listening",TcpState="Listening",ManagementState="Listening",ManagementListening=true,SnapshotUtc=DateTimeOffset.UtcNow,PolicyRevision=ReleaseRevision,PolicyLoaded=true,FilteringEnabled=!ReleaseInactive,EmergencySafeMode=ReleaseInactive,CommittedRuleCount=ReleasePolicy.GlobalBlockedDomains.Length,ActiveRuleCount=ReleaseInactive?0:ReleasePolicy.GlobalBlockedDomains.Length,PolicyRestoreState="Restored"},ReleaseJson);
                        }
                    }
                    if(status!=200)body="{\"error\":\"isolated mock failure\"}";
                    var data=Encoding.UTF8.GetBytes(body);var headers=Encoding.ASCII.GetBytes($"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {data.Length}\r\nConnection: keep-alive\r\n\r\n");
                    await ssl.WriteAsync(headers,budget.Token);await ssl.WriteAsync(data,budget.Token);Interlocked.Add(ref Bytes,headers.Length+data.Length);
                }
                finally{Interlocked.Decrement(ref Active);}
                }
            }
            catch(Exception ex)when(ex is IOException or AuthenticationException or OperationCanceledException or ObjectDisposedException){}
        }
    }
    public object Payload(string path,string scene)
    {
        var now=DateTimeOffset.UtcNow;var snapshot=scene=="Stale"?now.AddMinutes(-5):now;int count=scene=="Empty"?0:scene=="Many"?1500:Generation>=2?3:2;
        const string device="10000000-0000-0000-0000-000000000001";
        object[] registrations=scene=="Empty"?[]:[new{deviceId=device,name=Generation>=3?"Átnevezett labor TV":"Labor TV",mac="02:00:00:00:00:01",metadata=new{alias=Generation>=3?"Átnevezett labor TV":"Labor TV"}}];
        object Lan(int i)=>new{observationDeviceId=$"20000000-0000-0000-0000-{i+1:000000000000}",confidence="OBSERVED",presence="OBSERVED",lastObservedUtc=now,identity=new{deviceId=i==0?device:null,friendlyName=i==0?(Generation>=3?"Átnevezett labor TV":"Labor TV"):"Labor megfigyelés "+i,confidence=i==0?"USER-CONFIRMED":"UNKNOWN"},evidence=new[]{new{address="192.0.2."+(i+10),provenance="OBSERVED: isolated kernel fixture",observedAtUtc=now}}};
        var discoveries=Enumerable.Range(0,scene=="DeviceGone"?0:Math.Min(count,32)).Select(Lan).ToArray();if(scene=="Duplicate"&&discoveries.Length>0)discoveries=discoveries.Concat([discoveries[0]]).ToArray();
        var events=Enumerable.Range(0,scene=="Configured"?0:count).Select(i=>new{request=new{correlationId=$"30000000-0000-0000-0000-{i+1:000000000000}",receivedAtUtc=now.AddMinutes(-i%60)},deviceId=(string?)null,identityState="Unknown",domain=i%2==0?"video.example.invalid":"updates.example.invalid",policyRevision=75,blocked=i%3==0,reason=i%3==0?"GlobalBlock":"GlobalAllow",decisionChain=Array.Empty<object>(),evidenceTruncated=false}).ToArray();
        return path switch
        {
            "/dns/status"=>new{instanceId=Instance,snapshotUtc=snapshot,runtimeState="Running",udpState="Listening",tcpState="Listening",ipv6UdpState="Listening",ipv6TcpState="Listening",policyRevision=75,policyLoaded=true,filteringEnabled=true,emergencySafeMode=false,lastUpstreamOutcome="Response",upstreamHealth="NotMeasured",persistenceFault=""},
            "/v2/capabilities"=>new{apiVersion=2,ipv4DeviceEnforcement=true,ipv6DeviceEnforcement=false,fullPolicyReadback=true,optimisticConcurrency=true},
            "/v2/policy"=>new{instanceId=Instance,revision=75,policy=new{schemaVersion=3,devices=registrations,globalBlockedDomains=new[]{"video.example.invalid"},overrides=Array.Empty<object>()}},
            "/v2/bindings"=>new{generation=1,observations=Array.Empty<object>()},
            "/v2/discovery"=>discoveries,
            "/v2/diagnostics"=>new{instanceId=Instance,snapshotUtc=snapshot,health="Healthy",counters=new{received=1234,policyBlocked=18,allowed=1216},resources=new{cpuPercent=.4,workingSetBytes=120*1048576},upstreamLatency=new{samples=12,p50Ms=11.2,p95Ms=29.4},components=Array.Empty<object>()},
            "/v2/dns-observations"=>new{capacity=64,observations=events},
            "/v3/activity"=>new{schemaVersion=1,observedAtUtc=snapshot,retentionHours=24,maximumBuckets=256,buckets=Enumerable.Range(0,6).Select(i=>new{deviceId=(string?)null,serviceId=(string?)null,windowStartUtc=new DateTimeOffset(now.Year,now.Month,now.Day,now.Hour,now.Minute/5*5,0,TimeSpan.Zero).AddMinutes(-i*5),allowed=10+i,blocked=i,failed=0,ambiguousService=false}).ToArray()},
            "/v2/operational-events?after=0"=>new{schemaVersion=1,instanceId=Instance,latestSequence=1,cursorGap=false,events=scene=="Empty"?Array.Empty<object>():new object[]{new{sequence=1,instanceId=Instance,incidentId="mock-incident",component="Management",type="Recovery",severity="Info",occurredAtUtc=now,state="Healthy",summaryId="mock-restored",recoveryOf=(string?)null}}},
            _=>new{error="unsupported"}
        };
    }
    public async ValueTask DisposeAsync(){stop.Cancel();listener.Stop();if(loop!=null)await loop;await Task.WhenAll(clients.Values);certificate.Dispose();}
}
