using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using System.Text;
internal static class FingerprintTests
{
 public static void Run(Action<string,Action> test)
 {
  void Check(bool value){if(!value)throw new Exception("Fingerprint invariant failed");}
  var now=DateTimeOffset.UtcNow;
  test("inventory expiry is independent from registry and returning evidence is safe",()=>{
   var id=Guid.NewGuid();var registration=new DeviceRegistration(id,"Fixture console","02:DE:AD:BE:EF:01","fixture","Explicit fixture"){Metadata=new("Named console","Owner","Console","Room")};
   var policy=FullDnsPolicy.Empty with{SchemaVersion=3,Devices=[registration],Program=PolicyProgram.Empty};
   var store=new LanObservationStore();var evidence=new NetworkIdentityEvidence("192.0.2.1","02:DE:AD:BE:EF:01","fixture","OBSERVED fixture",now){NeighborState="STALE"};
   var first=store.Observe([evidence],now);Check(DeviceIdentityProjection.Apply(first,policy)[0].Identity!.DeviceId==id);
   Check(store.Observe([],now.AddMinutes(11)).Length==0 && policy.Devices[0].Metadata!.Type=="Console");
   var returning=store.Observe([evidence with{ObservedAtUtc=now.AddMinutes(12)}],now.AddMinutes(12));Check(DeviceIdentityProjection.Apply(returning,policy)[0].Identity!.DeviceId==id);
   var duplicate=returning[0] with{ObservationDeviceId=Guid.NewGuid()};Check(DeviceIdentityProjection.Apply([returning[0],duplicate],policy).All(d=>d.Identity!.DeviceId==null));
   var ipOnly=returning[0] with{Evidence=[evidence with{Mac=""}]};Check(DeviceIdentityProjection.Apply([ipOnly],policy)[0].Identity!.DeviceId==null);
   var forgotten=DeviceInventory.Forget(policy,id);Check(forgotten.Devices.Length==0 && DeviceIdentityProjection.Apply(returning,forgotten)[0].Identity!.State=="Provisional");
  });
  test("inventory forget cleans dependent references while preserving shared policy",()=>{
   var id=Guid.NewGuid();var other=Guid.NewGuid();var group=Guid.NewGuid();var only=Guid.NewGuid();var shared=Guid.NewGuid();
   var policy=FullDnsPolicy.Empty with{SchemaVersion=3,GlobalBlockedDomains=["fixture.invalid"],Devices=[new(id,"A",null,"fixture","User"),new(other,"B",null,"fixture","User")],Overrides=[new(id,"device.invalid",DeviceDomainRuleState.Block),new(other,"other.invalid",DeviceDomainRuleState.Allow)],
    Program=new([new(group,"Shared group",[id,other],[])],[],[new(only,"Only removed",true,true,false,[id],[],[]),new(shared,"Shared",true,true,false,[id,other],[],[])],[new(Guid.NewGuid(),only,"Only schedule",true,"UTC",[DayOfWeek.Monday],60,120)])};
   var result=DeviceInventory.Forget(policy,id);Check(result.Devices.Single().DeviceId==other && result.Overrides.Single().DeviceId==other && result.GlobalBlockedDomains.SequenceEqual(policy.GlobalBlockedDomains));
   Check(result.Program!.Groups.Single().DeviceIds.SequenceEqual([other]) && result.Program.Profiles.Single().ProfileId==shared && result.Program.Schedules.Length==0);
  });
  test("fingerprint every supported weak category and model-only IoT audited",()=>{
   foreach(var type in DeviceTypes.All.Where(t=>t.HostnameHints.Length>0))foreach(var hint in type.HostnameHints){var c=DeviceClassifier.Classify([new("192.0.2.1","Hostname","Hostname","fixture-"+hint,now)],now);Check(c.DeviceType==type.Id && c.Confidence=="Low");}
   Check(DeviceTypes.All.Single(t=>t.Id=="IoT").HostnameHints.Length==0);
   Check(DeviceClassifier.Classify([new("192.0.2.1","Hostname","Hostname","fixture-iot",now)],now).DeviceType=="Unknown");
  });
  test("fingerprint all strong roles and compatible media categories audited",()=>{
   foreach(var service in new[]{"_ipp._tcp.local","_ipps._tcp.local","_printer._tcp.local"})Check(DeviceClassifier.Classify([new("192.0.2.1","mDNS","Service",service,now)],now).DeviceType=="Printer");
   foreach(var role in new[]{"InternetGatewayDevice","WANConnectionDevice"}){var c=DeviceClassifier.Classify([new("192.0.2.1","SSDP","DeviceRole","urn:schemas-upnp-org:device:"+role+":1",now)],now);Check(c.DeviceType=="Network" && c.Confidence=="Medium");}
   foreach(var pair in new[]{("TV","tv"),("Streaming","settop"),("Speaker","speaker")}){var c=DeviceClassifier.Classify([new("192.0.2.1","SSDP","Advertised friendlyName","fixture-"+pair.Item2,now),new("192.0.2.1","SSDP","DeviceRole","urn:schemas-upnp-org:device:MediaRenderer:1",now)],now);Check(c.DeviceType==pair.Item1 && c.Confidence=="Medium");}
  });
  test("fingerprint reliable summary survives stale evidence without online or identity claim",()=>{
   var memory=new ClassificationMemory();var id=Guid.NewGuid();var evidence=new FingerprintEvidence("192.0.2.1","mDNS","Service","_ipp._tcp.local",now);
   var c=DeviceClassifier.Classify([evidence],now);var retained=memory.Update(id,c,now)!;
   Check(retained.Classification.Evidence.Length==0 && retained.Provenance.Length>0);
   var repeated=memory.Update(id,DeviceClassifier.Classify([evidence],now.AddMinutes(1)),now.AddMinutes(1))!;Check(repeated.Classification.AssessedAtUtc==now);
   var empty=DeviceClassifier.Classify([],now.AddMinutes(6));retained=memory.Update(id,empty,now.AddMinutes(6))!;
   var stale=DeviceTypes.Present("",empty,[],now.AddMinutes(6),retained);Check(stale.Type.Id=="Printer" && stale.EvidenceState=="STALE" && stale.LastClassifiedUtc==now && stale.Confidence=="Medium");
   Check(DeviceTypes.Present("Unknown",empty,[],now.AddMinutes(6),retained).Source=="USER-CONFIRMED");
   var conflict=DeviceClassifier.Classify([evidence with{ObservedAtUtc=now.AddMinutes(6)},new("192.0.2.1","Hostname","Hostname","fixture-phone",now.AddMinutes(6))],now.AddMinutes(6));
   Check(DeviceTypes.Present("",conflict,[],now.AddMinutes(6),memory.Update(id,conflict,now.AddMinutes(6))).EvidenceState=="CONFLICT");
   Check(memory.Update(Guid.NewGuid(),empty,now.AddMinutes(6)) is null);
   var changed=DeviceClassifier.Classify([new("192.0.2.1","SSDP","DeviceRole","urn:schemas-upnp-org:device:InternetGatewayDevice:1",now.AddMinutes(7))],now.AddMinutes(7));
   Check(memory.Update(id,changed,now.AddMinutes(7))!.Classification.DeviceType=="Network");
   Check(memory.Update(id,empty,now.AddHours(25)) is null && new ClassificationMemory().Count==0);
  });
  test("fingerprint classification summary retention is bounded",()=>{var memory=new ClassificationMemory();var c=DeviceClassifier.Classify([new("192.0.2.1","mDNS","Service","_ipp._tcp.local",now)],now);for(var i=0;i<100;i++)memory.Update(Guid.NewGuid(),c,now);Check(memory.Count==64);});
  FingerprintEvidence E(string provider,string kind,string value)=>new("192.0.2.1",provider,kind,value,now);
  test("fingerprint class-specific single protocol is inferred Medium",()=>{var c=DeviceClassifier.Classify([E("mDNS","Service","_ipp._tcp.local")],now);Check(c.DeviceType=="Printer" && c.Confidence=="Medium" && c.Source=="INFERRED");});
  test("fingerprint independent protocol agreement is High",()=>{var c=DeviceClassifier.Classify([E("mDNS","Service","_ipps._tcp.local"),E("SSDP","DeviceRole","urn:schemas-upnp-org:device:Printer:1")],now);Check(c.DeviceType=="Printer" && c.Confidence=="High");});
  test("fingerprint duplicated source never increases confidence",()=>{var e=E("mDNS","Service","_ipp._tcp.local");Check(DeviceClassifier.Classify([e,e,e],now).Confidence=="Medium");});
  test("fingerprint hostname-only evidence is Low",()=>{Check(DeviceClassifier.Classify([E("Hostname","Hostname","living-room-tv")],now).Confidence=="Low");});
  test("fingerprint conflicts retain evidence and become Unknown",()=>{var c=DeviceClassifier.Classify([E("Hostname","Hostname","my-phone"),E("mDNS","Service","_ipp._tcp.local")],now);Check(c.DeviceType=="Unknown" && c.Evidence.Length==2 && c.Reason.Contains("Conflicting"));});
  test("fingerprint Android-TV service alone cannot distinguish a TV from streaming box",()=>{Check(DeviceClassifier.Classify([E("mDNS","Service","_androidtvremote2._tcp.local")],now).DeviceType=="Unknown");});
  test("fingerprint advertised TV hint plus renderer remains inferred Medium",()=>{var c=DeviceClassifier.Classify([E("SSDP","Advertised friendlyName","[TV] Anonymous fixture"),E("SSDP","DeviceRole","urn:schemas-upnp-org:device:MediaRenderer:1")],now);Check(c.DeviceType=="TV" && c.Confidence=="Medium");});
  test("fingerprint generic media and manufacturer do not imply TV or phone",()=>{foreach(var vendor in new[]{"Apple","Samsung","Microsoft","Unknown vendor"})Check(DeviceClassifier.Classify([E("SSDP","Advertised manufacturer",vendor),E("SSDP","DeviceRole","urn:schemas-upnp-org:device:MediaRenderer:1"),E("mDNS","Service","_googlecast._tcp.local")],now).DeviceType=="Unknown");});
  test("fingerprint randomized MAC is not vendor classification",()=>{Check(DeviceClassifier.Classify([E("Neighbour","MAC","02:DE:AD:BE:EF:01")],now).DeviceType=="Unknown");});
  test("fingerprint unsupported and empty evidence fall back Unknown",()=>{Check(DeviceClassifier.Classify([],now).DeviceType=="Unknown" && DeviceClassifier.Classify([E("mDNS","Service","phone-printer._arbitrary._tcp.local")],now).DeviceType=="Unknown");});
  test("fingerprint evidence expires and future timestamps withheld",()=>{var e=E("mDNS","Service","_ipp._tcp.local");Check(DeviceClassifier.Classify([e with{ObservedAtUtc=now.AddMinutes(-6)},e with{ObservedAtUtc=now.AddMinutes(1)}],now).DeviceType=="Unknown");});
  test("fingerprint explicit Unknown and corrected user type override inference",()=>{var c=DeviceClassifier.Classify([E("mDNS","Service","_ipp._tcp.local")],now);Check(DeviceTypes.Present("Phone",c,[],now).Type.Id=="Phone" && DeviceTypes.Present("Unknown",c,[],now).Source=="USER-CONFIRMED" && DeviceTypes.Present("",c,[],now.AddMinutes(6)).Type.Id=="Unknown");});
  test("fingerprint hostile and excess evidence do not classify",()=>{Check(DeviceClassifier.Classify([E("Hostname","Hostname","phone\nprinter"),E("Hostname","Hostname",new string('x',257))],now).DeviceType=="Unknown");Check(DeviceClassifier.Classify(Enumerable.Range(0,33).Select(i=>E("mDNS","Service",i==0?"_ipp._tcp.local":"unsupported"+i)),now).DeviceType=="Unknown");});
  test("fingerprint safe SSDP locations are literal peer-only",()=>{Check(FingerprintDiscovery.SafeLocation("http://192.0.2.1:8008/description.xml","192.0.2.1"));foreach(var url in new[]{"http://other.example/","https://192.0.2.1/","http://192.0.2.2/","http://u:p@192.0.2.1/","http://127.0.0.1/","file:///etc/passwd"})Check(!FingerprintDiscovery.SafeLocation(url,"192.0.2.1"));});
  test("fingerprint XML rejects DTD expansion and oversize",()=>{Check(FingerprintDiscovery.ParseDescription(Encoding.UTF8.GetBytes("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><root>&e;</root>"),"192.0.2.1",now).Length==0);Check(FingerprintDiscovery.ParseDescription(new byte[16385],"192.0.2.1",now).Length==0);});
  test("fingerprint safe UPnP description role is explicit",()=>{var e=FingerprintDiscovery.ParseDescription(Encoding.UTF8.GetBytes("<root><device><deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType><manufacturer>Untrusted brand</manufacturer></device></root>"),"192.0.2.1",now);Check(e.Length==2 && DeviceClassifier.Classify(e,now).DeviceType=="Printer");});
  test("fingerprint malformed SSDP does not crash or classify",()=>{foreach(var packet in new[]{new byte[9000],Encoding.UTF8.GetBytes("bad"),Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nST: a\r\nST: b\r\n")})Check(FingerprintDiscovery.ParseSsdp(packet,"192.0.2.1",now).Length==0);});
  test("fingerprint malformed mDNS compression loops and fuzz are bounded",()=>{var random=new Random(7);for(var i=0;i<1000;i++){var bytes=new byte[random.Next(0,512)];random.NextBytes(bytes);FingerprintDiscovery.ParseMdns(bytes,"192.0.2.1",now);}Check(FingerprintDiscovery.ParseMdns(new byte[8193],"192.0.2.1",now).Length==0);});
  test("fingerprint valid mDNS service record parses exact semantics",()=>{var name=Encoding.ASCII.GetBytes("_ipp");var query=FingerprintDiscovery.MdnsQuery();using var m=new MemoryStream();m.Write(new byte[]{0,0,128,0,0,0,0,1,0,0,0,0});m.Write(query.AsSpan(12,query.Length-16));m.Write(new byte[]{0,12,0,1,0,0,0,60,0,17,4});m.Write(name);m.Write(new byte[]{4,(byte)'_', (byte)'t',(byte)'c',(byte)'p',5,(byte)'l',(byte)'o',(byte)'c',(byte)'a',(byte)'l',0});var result=FingerprintDiscovery.ParseMdns(m.ToArray(),"192.0.2.1",now);Check(result.Length==1 && result[0].Value=="_ipp._tcp.local");});
  test("fingerprint cancelled refresh has bounded termination and retains no fabricated evidence",()=>{using var cancel=new CancellationTokenSource();cancel.Cancel();try{FingerprintDiscovery.RefreshAsync(cancel.Token).GetAwaiter().GetResult();throw new Exception("Cancelled refresh unexpectedly executed");}catch(OperationCanceledException){}Check(FingerprintDiscovery.Snapshot(now).Length==0);});
  test("fingerprint fresh session has no persisted inferred evidence",()=>{Check(!FingerprintDiscovery.Snapshot(now).Any());});
 }
}
