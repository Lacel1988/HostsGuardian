using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class GlobalDomainRemediationTests
{
    private static void Check(bool value,string message){if(!value)throw new Exception(message);}
    private static readonly JsonSerializerOptions Options = new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase,PropertyNameCaseInsensitive=true};
    private sealed class Handler : HttpMessageHandler
    {
        public FullDnsPolicy Policy = PolicyCanonicalization.Canonicalize(new(2,["keep.invalid"],[new(Guid.NewGuid(),"Registered",null,"fixture","explicit")],[]));
        public long Revision=7; public int Writes; public bool Conflict,FailWrite,FailReadback,Inactive;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            object value;
            switch(request.RequestUri!.AbsolutePath)
            {
                case "/v2/policy": if(FailReadback && Writes>0)return new(HttpStatusCode.ServiceUnavailable); value=new FullPolicyRead(Revision,Policy,"fixture");break;
                case "/v2/capabilities":value=new{policySchemaVersion=2,fullPolicyReadback=true,optimisticConcurrency=true};break;
                case "/v2/policy/replace":
                    Writes++;if(FailWrite)return new(HttpStatusCode.ServiceUnavailable);
                    if(Conflict){Conflict=false;Revision++;Policy=PolicyCanonicalization.Canonicalize(Policy with{GlobalBlockedDomains=Policy.GlobalBlockedDomains.Add("concurrent.invalid")});return new(HttpStatusCode.Conflict);}
                    var p=JsonSerializer.Deserialize<FullPolicyReplace>(await request.Content!.ReadAsStringAsync(ct),Options)!;
                    Check(p.ExpectedRevision==Revision&&p.ExpectedInstanceId=="fixture","CAS bypass");Policy=p.Policy;Revision++;value=new{ok=true,revision=Revision};break;
                case "/health":value=new{engine="HostsGuardian.DnsEngine",apiVersion=1};break;
                case "/dns/status":value=new DnsServiceStatus{Implementation="HostsGuardian.DnsEngine",InstanceId="fixture",DnsPort=53,ApiPort=3000,PolicyRevision=Revision,PolicyLoaded=true,FilteringEnabled=!Inactive,EmergencySafeMode=Inactive,CommittedRuleCount=Policy.GlobalBlockedDomains.Length,ActiveRuleCount=Inactive?0:Policy.GlobalBlockedDomains.Length};break;
                default:throw new Exception("Unexpected endpoint");
            }
            return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(value,Options))};
        }
    }
    public static async Task Run(Func<string,Func<Task>,Task> test,string directory)
    {
        foreach(var mode in new[]{"new","already","conflict","write-failure","readback-failure","inactive"})
        await test("Single-domain reconciliation: "+mode,async()=>
        {
            var handler=new Handler{Conflict=mode=="conflict",FailWrite=mode=="write-failure",FailReadback=mode=="readback-failure",Inactive=mode=="inactive"};
            var registry=JsonSerializer.Serialize(handler.Policy.Devices);
            if(mode=="already")handler.Policy=handler.Policy with{GlobalBlockedDomains=handler.Policy.GlobalBlockedDomains.Add("youtube.com")};
            var service=new DnsEngineService(()=>new HttpClient(handler,false));var cfg=new DnsEngineConfig{Address="fixture.invalid",ApiToken=new string('a',64)};
            var result=await service.SetGlobalDomainAsync(cfg,"YouTube.com.",true);
            Check(handler.Policy.GlobalBlockedDomains.Contains("keep.invalid")&&JsonSerializer.Serialize(handler.Policy.Devices)==registry,"Unrelated policy removed");
            if(mode=="already")Check(result.Stored&&result.AlreadyCurrent&&handler.Writes==0,"Already blocked rewrote policy");
            if(mode=="conflict")Check(result.Stored&&handler.Writes==2&&handler.Policy.GlobalBlockedDomains.Contains("concurrent.invalid"),"Concurrent edit lost or retry unbounded");
            if(mode.EndsWith("failure"))Check(!result.Stored&&handler.Writes==1,"Ambiguous failure retried or falsely confirmed");
            else Check(result.Stored && result.Applied==(mode!="inactive"),"Saved/applied conflated");
            if(mode=="new"){var removed=await service.SetGlobalDomainAsync(cfg,"youtube.com",false);Check(removed.Stored&&!handler.Policy.GlobalBlockedDomains.Contains("youtube.com")&&handler.Policy.GlobalBlockedDomains.Contains("keep.invalid"),"Remove changed unrelated rule");}
        });
        await test("Real isolated TLS Engine -> UDP/TCP DNS -> persistence restart (no production)",async()=>
        {
            var tlsDirectory=Path.Combine(directory,"global-dns");Directory.CreateDirectory(tlsDirectory);
            using(var key=System.Security.Cryptography.RSA.Create(2048))
            {
                var req=new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=isolated-review",key,System.Security.Cryptography.HashAlgorithmName.SHA256,System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                var names=new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();names.AddIpAddress(IPAddress.Loopback);req.CertificateExtensions.Add(names.Build());
                req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(false,false,0,true));
                req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(new System.Security.Cryptography.OidCollection{new("1.3.6.1.5.5.7.3.1")},true));
                using var cert=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
                File.WriteAllText(Path.Combine(tlsDirectory,"temporary-cert.pem"),cert.ExportCertificatePem());File.WriteAllText(Path.Combine(tlsDirectory,"temporary-key.pem"),key.ExportPkcs8PrivateKeyPem());
                File.WriteAllText(Path.Combine(tlsDirectory,"temporary-token"),Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            }
            await using var f=new Phase5DTests.Fixture(tlsDirectory);
            using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var upstream=Task.Run(async()=>{try{while(!stop.IsCancellationRequested){var q=await f.Upstream.ReceiveAsync(stop.Token);var b=q.Buffer;b[2]=0x81;b[3]=0x80;await f.Upstream.SendAsync(b,q.RemoteEndPoint,stop.Token);}}catch(OperationCanceledException){} });
            await f.Api.StartAsync(stop.Token);await f.Dns.StartAsync(stop.Token);
            await using var tcp=new TcpDnsServer(f.Settings,f.Dns.RequestProcessor,f.Dns.RuntimeStatus);await tcp.StartAsync(stop.Token);
            var service=new DnsEngineService();var result=await service.SetGlobalDomainAsync(f.ClientConfig,"youtube.com",true,stop.Token);
            Check(result.Stored&&result.Applied,"Real policy not applied");
            static byte[] Query(string name){var b=new List<byte>{0x61,0x20,1,0,0,1,0,0,0,0,0,0};foreach(var s in name.Split('.')){b.Add((byte)s.Length);b.AddRange(Encoding.ASCII.GetBytes(s));}b.AddRange(new byte[]{0,0,1,0,1});return b.ToArray();}
            async Task<byte[]> Probe(string domain,bool stream){var q=Query(domain);if(!stream){using var client=new UdpClient();client.Connect(IPAddress.Loopback,f.Settings.DnsPort);await client.SendAsync(q,stop.Token);return(await client.ReceiveAsync(stop.Token)).Buffer;}using var t=new TcpClient();await t.ConnectAsync(IPAddress.Loopback,f.Settings.DnsPort,stop.Token);var s=t.GetStream();await s.WriteAsync(new byte[]{0,(byte)q.Length},stop.Token);await s.WriteAsync(q,stop.Token);var len=new byte[2];await s.ReadExactlyAsync(len,stop.Token);var answer=new byte[(len[0]<<8)|len[1]];await s.ReadExactlyAsync(answer,stop.Token);return answer;}
            foreach(var stream in new[]{false,true})
            {
                var blocked=await Probe("youtube.com",stream);Check(DnsProtocol.IsMatchingResponse(Query("youtube.com"),blocked)&&blocked[^4..].SequenceEqual(new byte[]{0,0,0,0}),"No sinkhole DNS answer");
                var allowed=await Probe("notyoutube.com",stream);Check(allowed.Length==Query("notyoutube.com").Length&&allowed[7]==0,"Domain matching broadened");
            }
            var restoredRules=new RuleStore("restarted");var restored=new PolicyApplicationService(restoredRules,new PolicyPersistence(f.Config.PolicyFilePath));restored.InitializeForStartup();
            Check(restored.State.GetSnapshot().Loaded&&restoredRules.IsBlocked("youtube.com")&&restored.ReadFullPolicy().Revision==result.Confirmation.Readback!.Revision,"WPF-independent disk restore failed");
            var noWrite=await service.SetGlobalDomainAsync(f.ClientConfig,"youtube.com",true,stop.Token);Check(noWrite.AlreadyCurrent&&noWrite.Confirmation.Readback!.Revision==result.Confirmation.Readback!.Revision,"Repeated click incremented revision");
            var remove=await service.SetGlobalDomainAsync(f.ClientConfig,"youtube.com",false,stop.Token);Check(remove.Stored&&(await Probe("youtube.com",false))[7]==0,"Removal did not reach DNS");
            stop.Cancel();await upstream;
        });
    }
}


