using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Services;
using HostsGuardian.Wpf.ViewModels;
internal static class RegistrationConsistencyTests
{
 public static void Run()
 {
  void Check(bool value,string reason){if(!value)throw new Exception(reason);}
  var folder=Path.Combine(Path.GetTempPath(),"HostsGuardian-registry-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
  UiPreferences.Use(new UiPreferences(Path.Combine(folder,"preferences.json")));
  var id=Guid.NewGuid();var registration=new DeviceRegistration(id,"Deleted alias","02:DE:AD:BE:EF:11","fixture","Explicit fixture"){Metadata=new("Deleted alias","Deleted owner","Console","Deleted room")};
  var policy=FullDnsPolicy.Empty with{SchemaVersion=3,Program=PolicyProgram.Empty,Devices=[registration]};
  var config=new AppConfig{DeviceDomainPolicy=policy,DnsEngine=new(){BaseUrl="https://fixture.invalid:3000",CredentialId="fixture"}};
  var store=new ConfigService(Path.Combine(folder,"config.json"));store.Save(config);
  var handler=new Handler();var service=new DnsEngineService(()=>new HttpClient(handler,false),new Credentials());
  var vm=new MainViewModel(store,false,new AuditLogService(Path.Combine(folder,"audit.log")),service);
  vm.Devices.Clear();var now=DateTimeOffset.UtcNow;var observation=new LanDeviceObservation(Guid.NewGuid(),"SESSION / PROVISIONAL","OBSERVED",now,now,
   [new("192.0.2.11",registration.Mac!,"observed-fixture","OBSERVED fixture",now){NeighborState="STALE"}]){Classification=new("TV","Medium","INFERRED","Category agrees with renderer",now,[])};
  var row=new DeviceVm(new NetworkDevice{Ip="192.0.2.11",Mac=registration.Mac!,Hostname="observed-fixture"},registration.Name,false){LanObservation=observation};row.ApplyRegistration(registration,policy);vm.Devices.Add(row);vm.SelectedDevice=row;
  Check(row.IsRegistered && row.ConfirmedType=="Console","Fixture registration not valid");
  Confirm(()=>vm.LoadFullPolicyCommand.Execute(null));Wait(vm);
  Check(store.Load().DeviceDomainPolicy.Devices.Length==0 && row.DeviceId==null && !row.IsRegistered,"Empty Engine import left orphan Known row");
  Check(row.Name=="" && row.ConfirmedType=="" && !row.TypeEdited && row.LanObservation!.ObservationDeviceId==observation.ObservationDeviceId,"Deleted metadata restored or observation lost");
  Check(row.TypeAssessment.Type.Id=="TV" && row.TypeAssessment.Source=="INFERRED","Import lost retained classification");
  // Defensive save recovery if a stale ID is introduced independently of import.
  row.DeviceId=id;row.Name="Must not resurrect";row.ConfirmedType="Console";vm.SaveDevicesCommand.Execute(null);
  Check(row.DeviceId==null && row.Name=="" && row.ConfirmedType=="" && vm.HasError && store.Load().DeviceDomainPolicy.Devices.Length==0,"Orphan save silently succeeded");
  row.DeviceId=id;Check(!row.IsRegistered,"Arbitrary DeviceId became visually Known");
  Confirm(()=>vm.RegisterSelectedDeviceCommand.Execute(null));
  Check(row.IsRegistered && row.DeviceId!=id && store.Load().DeviceDomainPolicy.Devices.Length==1,"Explicit re-registration failed");
  row.Name="New explicit alias";row.SelectedTypeId="TV";
  Check(vm.HasUnsavedIdentityEdits && vm.DeviceWorkflowState=="Editing","Unsaved identity edits not exposed");
  Confirm(()=>vm.LoadFullPolicyCommand.Execute(null),false);
  Check(row.Name=="New explicit alias" && vm.HasUnsavedIdentityEdits && row.IsRegistered,"Cancelled import discarded local changes");
  vm.PushDnsCommand.Execute(null);Wait(vm);Check(handler.LastReplace==null && vm.HasUnsavedIdentityEdits,"Send silently omitted unsaved identity");
  vm.SaveDevicesCommand.Execute(null);
  Check(!vm.HasUnsavedIdentityEdits && vm.DeviceWorkflowState=="Saved","Saved local changes misrepresented as confirmed");
  var saved=store.Load().DeviceDomainPolicy.Devices.Single();Check(saved.Metadata?.Alias=="New explicit alias" && saved.Metadata.Type=="TV" && row.TypeAssessment.Source=="USER-CONFIRMED","Re-registered metadata not persisted");
  vm.PushDnsCommand.Execute(null);Wait(vm);
  Check(handler.LastReplace?.Policy.Devices.Single().DeviceId==saved.DeviceId && handler.Policy.Devices.Single().Metadata!.Alias==saved.Metadata.Alias,"Complete delivery omitted registration/metadata");
  Check(vm.DeviceWorkflowState=="Confirmed","Verified delivery missing confirmed state");
  var projected=DeviceIdentityProjection.Apply([observation],handler.Policy).Single();
  Check(projected.Identity!.State=="Registered" && projected.Identity.FriendlyName==saved.Metadata.Alias && projected.Identity.DeviceType=="TV","Delivered policy cannot project identity to Monitor");
  handler.Fail=true;vm.PushDnsCommand.Execute(null);Wait(vm);
  Check(vm.DeviceWorkflowState=="Failed" && row.IsRegistered,"Failed Engine request fabricated success or erased registration");handler.Fail=false;
  Confirm(()=>vm.LoadFullPolicyCommand.Execute(null));Wait(vm);Check(row.IsRegistered && row.DeviceId==saved.DeviceId && row.ConfirmedType=="TV","Valid readback lost registration");
  Confirm(()=>vm.ForgetSelectedDeviceCommand.Execute(null));Check(store.Load().DeviceDomainPolicy.Devices.Length==0,"Forget failed");
  Check(DeviceIdentityProjection.Apply([observation],store.Load().DeviceDomainPolicy).Single().Identity!.State=="Provisional","Forget resurrected metadata");
  var ambiguousA=new DeviceVm(new NetworkDevice{Ip="192.0.2.11",Mac=registration.Mac!},null,false){LanObservation=observation};ambiguousA.ApplyRegistration(saved,handler.Policy);
  var ambiguousB=new DeviceVm(new NetworkDevice{Ip="192.0.2.12",Mac=registration.Mac!},null,false){LanObservation=observation with{ObservationDeviceId=Guid.NewGuid()}};
  var separate=DeviceInventoryView.Merge([ambiguousA,ambiguousB],handler.Policy);
  Check(separate.Count(d=>d.IsRegistered)==1 && separate.Single(d=>d.IsRegistered).LanObservation is null && separate.Count(d=>!d.IsRegistered)==2,"Ambiguous observations silently remained registered");
  Console.WriteLine("PASS device UX dirty/save/send/confirmed/failure states and cancelled import preserve identity edits");
  Console.WriteLine("PASS actual WPF import reconciles orphan, save exposes recovery, re-registration persists metadata, complete delivery/readback and Forget preserve authoritative registry");
  vm.Dispose();
 }
 private static void Wait(MainViewModel vm)
 {
  var pending=typeof(MainViewModel).GetField("_engineRequestPending",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!;
  var until=DateTime.UtcNow.AddSeconds(5);
  while((bool)pending.GetValue(vm)! && DateTime.UtcNow<until){Dispatcher.CurrentDispatcher.Invoke(()=>{},DispatcherPriority.Background);Thread.Sleep(1);}
  if((bool)pending.GetValue(vm)!)throw new Exception("Isolated request did not finish");
 }
 private static void Confirm(Action action,bool accept=true)
 {
  var timer=new DispatcherTimer{Interval=TimeSpan.FromMilliseconds(20)};var ticks=0;
  timer.Tick+=(_,_)=>{var dialog=Application.Current.Windows.OfType<Window>().FirstOrDefault(w=>w.Content is DockPanel panel && panel.Children.OfType<StackPanel>().Any(s=>s.Children.OfType<Button>().Any(b=>b.Name=="ConfirmButton")));
   if(dialog is not null){timer.Stop();((DockPanel)dialog.Content).Children.OfType<StackPanel>().SelectMany(s=>s.Children.OfType<Button>()).Single(b=>b.Name==(accept?"ConfirmButton":"DeclineButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));}
   else if(++ticks>250){timer.Stop();throw new Exception("Isolated confirmation did not appear");}};
  timer.Start();try{action();}finally{timer.Stop();}
 }
 private sealed class Handler:HttpMessageHandler
 {
  public bool Fail;
  public FullDnsPolicy Policy=FullDnsPolicy.Empty;public long Revision=1;public FullPolicyReplace? LastReplace;
  private readonly JsonSerializerOptions _options=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase,PropertyNameCaseInsensitive=true};
  protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
  {
   if(Fail)return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
   object body=request.RequestUri!.AbsolutePath switch{
    "/health"=>new{engine="HostsGuardian.DnsEngine",apiVersion=1},
    "/v2/capabilities"=>new{supportedPolicySchemas=new[]{2,3},policySchemaVersion=2,fullPolicyReadback=true,optimisticConcurrency=true},
    "/v2/policy"=>new FullPolicyRead(Revision,Policy,"fixture-instance"),
    "/dns/status"=>new DnsServiceStatus{Implementation="HostsGuardian.DnsEngine",InstanceId="fixture-instance",DnsPort=53,ApiPort=3000,PolicyRevision=Revision,PolicyLoaded=true,FilteringEnabled=true,PolicySchemaVersion=Policy.SchemaVersion},
    "/v2/policy/replace"=>await Replace(request,token),_=>throw new Exception("Unexpected fixture endpoint")};
   return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(body,_options))};
  }
  private async Task<object> Replace(HttpRequestMessage request,CancellationToken token)
  {LastReplace=JsonSerializer.Deserialize<FullPolicyReplace>(await request.Content!.ReadAsStringAsync(token),_options)!;
   if(LastReplace.ExpectedRevision!=Revision)throw new Exception("Revision guard failed");Policy=PolicyCanonicalization.Canonicalize(LastReplace.Policy);Revision++;return new{ok=true,revision=Revision};}
 }
 private sealed class Credentials:ICredentialStore
 {public string? Read(string id)=>new string('a',64);public void Write(string id,string token)=>throw new NotSupportedException();public void Delete(string id)=>throw new NotSupportedException();}
}
