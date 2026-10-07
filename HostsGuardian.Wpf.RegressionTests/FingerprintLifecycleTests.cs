using System.Text.Json;
using System.Net;
using System.Net.Http;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.ViewModels;
internal static class FingerprintLifecycleTests
{
 public static void Run()
 {
  void Check(bool value,string reason){if(!value)throw new Exception(reason);}
  var now=DateTimeOffset.UtcNow;
  FingerprintEvidence[] fingerprints=[new("192.0.2.7","SSDP","Advertised friendlyName","[TV] Samsung fixture",now),new("192.0.2.7","SSDP","DeviceRole","urn:schemas-upnp-org:device:MediaRenderer:1",now),new("192.0.2.7","mDNS","Service","_airplay._tcp.local",now)];
  var store=new LanObservationStore(t=>fingerprints.Where(e=>e.ObservedAtUtc>=t.AddMinutes(-5)).ToArray());
  var network=new NetworkIdentityEvidence("192.0.2.7","02:DE:AD:BE:EF:07","","OBSERVED fixture",now){Interface="fixture",NeighborState="STALE"};
  var first=store.Observe([network],now).Single();
  Check(first.Classification!.DeviceType=="TV" && first.Classification.Confidence=="Medium","TV fixture did not classify");
  var options=new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase,PropertyNameCaseInsensitive=true};
  var vm=new DeviceVm(new NetworkDevice{Ip=network.Address},null,false){LanObservation=JsonSerializer.Deserialize<LanDeviceObservation>(JsonSerializer.Serialize(first with{LastReliableClassification=null},options),options)};
  var payload=JsonSerializer.Serialize(new[]{first with{LastReliableClassification=null}},options);
  var handler=new Handler(()=>payload);var service=new DnsEngineService(()=>new HttpClient(handler,false));
  var config=new DnsEngineConfig{BaseUrl="https://fixture.invalid:3000",ApiToken=new string('a',64)};
  var apiFirst=service.ReadLanDiscoveryAsync(config).GetAwaiter().GetResult().Single();
  Check(apiFirst.LastReliableClassification?.Classification.DeviceType=="TV","Client API read model omitted fresh summary");
  var expiredDisplay=DeviceTypes.Present("",vm.LanObservation!.Classification,[],now.AddMinutes(6),vm.LanObservation.LastReliableClassification);
  Check(expiredDisplay.Type.Id=="TV" && expiredDisplay.EvidenceState=="STALE","Passive UI expiry without another API refresh erased TV");
  Check(vm.TypeAssessment.Type.Id=="TV","WPF failed fresh readback");
  for(var minutes=6;minutes<=7;minutes++){
   var snapshot=store.Observe([network with{ObservedAtUtc=now.AddMinutes(minutes)}],now.AddMinutes(minutes)).Single();
   Check(snapshot.ObservationDeviceId==first.ObservationDeviceId && snapshot.Classification!.DeviceType=="Unknown","Production observation/classifier expiry not reproduced");
   Check(snapshot.LastReliableClassification?.Classification.DeviceType=="TV","New Engine producer lost retained state");
   payload=JsonSerializer.Serialize(new[]{snapshot with{LastReliableClassification=null}},options);
   var readback=service.ReadLanDiscoveryAsync(config).GetAwaiter().GetResult().Single();
   var rebuilt=new DeviceVm(new NetworkDevice{Ip=network.Address},null,false){LanObservation=DeviceIdentityProjection.Apply([readback],FullDnsPolicy.Empty).Single()};
   var merged=DeviceInventoryView.Merge([rebuilt],FullDnsPolicy.Empty).Single();
   Check(merged.TypeAssessment.Type.Id=="TV" && merged.TypeAssessment.EvidenceState=="STALE","Actual API/reconstruction/inventory merge erased retained inference");
   // Legacy producer DTO lacks retained state. Actual WPF row refresh must still preserve it.
   vm.LanObservation=JsonSerializer.Deserialize<LanDeviceObservation>(JsonSerializer.Serialize(snapshot with{LastReliableClassification=null},options),options);vm.RefreshTypePresentation();
   Check(vm.TypeAssessment.Type.Id=="TV" && vm.TypeAssessment.EvidenceState=="STALE" && vm.Icon=="device-tv","Unknown refresh erased reliable TV inference");
   Check(vm.PresenceText.Contains("online state unproven"),"Cached neighbour implied online");
  }
  vm.ConfirmedType="Console";vm.RefreshTypePresentation();Check(vm.TypeAssessment.Source=="USER-CONFIRMED" && vm.TypeAssessment.Type.Id=="Console","User type lost");
  for(var minutes=8;minutes<=9;minutes++){
   vm.LanObservation=store.Observe([network with{ObservedAtUtc=now.AddMinutes(minutes)}],now.AddMinutes(minutes)).Single();vm.RefreshTypePresentation();
   Check(vm.TypeAssessment.Source=="USER-CONFIRMED" && vm.TypeAssessment.Type.Id=="Console","Refresh overwrote confirmed type");
  }
  fingerprints=[new("192.0.2.7","mDNS","Service","_ipp._tcp.local",DateTimeOffset.UtcNow),new("192.0.2.7","Hostname","Hostname","fixture-tv",DateTimeOffset.UtcNow)];
  var conflict=store.Observe([network],DateTimeOffset.UtcNow).Single();vm.ConfirmedType="";vm.LanObservation=conflict;
  Check(vm.TypeAssessment.Type.Id=="TV" && vm.TypeAssessment.EvidenceState=="CONFLICT","Stronger contradictory evidence hidden or promoted to certainty");
  var different=conflict with{ObservationDeviceId=Guid.NewGuid(),Classification=new("Unknown","Unknown","INFERRED","No evidence",now,[]),LastReliableClassification=null};
  payload=JsonSerializer.Serialize(new[]{different},options);Check(service.ReadLanDiscoveryAsync(config).GetAwaiter().GetResult().Single().LastReliableClassification is null,"IP-only new session inherited old inference");
  Console.WriteLine("PASS production observation → JSON readback → WPF refresh lifecycle retains TV through two Unknown cycles and preserves user authority");
 }
 private sealed class Handler(Func<string> body):HttpMessageHandler
 {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(body())});}
}
