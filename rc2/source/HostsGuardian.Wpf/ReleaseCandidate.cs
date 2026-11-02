using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
using DesignPrototype.Engine;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace DesignPrototype;

public sealed partial class PrototypeWindow
{
    public bool ReleaseCandidate{get;set;}
    public bool GlobalBusy{get;private set;}
    public string GlobalResult{get;private set;}="";
    string globalDraft="";TextBlock? globalFeedback;Button? blockButton,restoreButton;
    void InitializeRelease()=>InitializeLoginUat();
    void ReleaseOfflinePage()
    {
        engineTexts.Clear();page.Children.Clear();CurrentTable=null;EngineGrid=null;
        page.Children.Add(Ui.Text("HOSTSGUARDIAN V2.3.1 / UAT",12,"#9AC5FF",true));
        page.Children.Add(Ui.Text(Loc.T(CurrentView),27,bold:true));
        if(CurrentView=="Beállítások"){ReleaseSettingsPage();return;}
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Nincs csatlakoztatott adatforrás","No connected data source"),23,bold:true),Ui.Text(Loc.Pick("A rendszer állapota nem ismert. Ez nem jelent igazolt védelmet, és nem jelent nulla eseményt sem.","System state is unknown. This does not mean verified protection or zero events.")),Ui.Badge("UNKNOWN / UNAVAILABLE","#FFD58A"),Ui.Text(Loc.Pick("A beállításokban kapcsolódhatsz a meglévő Engine-hez. A kapcsolat csak olvas; a szabályírás külön jóváhagyásra vár.","Connect to the configured Engine in Settings. Data is read-only; writes require separate approval.")),Actions(("Beállítások",()=>Navigate("Beállítások"),"RcOpenSettings")))));
        status.Text="UAT • NINCS KAPCSOLAT • UNKNOWN";
    }
    void ReleaseSettingsPage()=>UatSettingsPage();
    public async Task StartReleaseMock(){await StartMockEngine(false);DetailsButton.IsEnabled=true;scenarioButton.IsEnabled=false;Navigate("Áttekintés");}
    void ReleaseDomainsPage()
    {
        page.Children.Add(Ui.Text(Loc.Pick("Globális DNS-szabályok","Global DNS rules"),21,bold:true));
        page.Children.Add(Ui.Text(Loc.Pick("A tiltás minden érintett DNS-kérésre vonatkozik. A feloldás a megadott domain globális tiltását távolítja el; más szabály továbbra is tilthatja.","Block applies globally to matching DNS requests. Restore removes this domain's global block; other rules may still block it.")));
        var input=Input(globalDraft,"RcGlobalDomain");input.TextChanged+=(_,_)=>globalDraft=input.Text;
        page.Children.Add(Field(Loc.Pick("Domainnév (például example.invalid)","Domain name (for example example.invalid)"),input));
        blockButton=Ui.Button(Loc.Pick("Globális tiltás","Global block"),()=>ConfirmGlobal(true),"RcGlobalBlock");restoreButton=Ui.Button(Loc.Pick("Globális tiltás feloldása","Restore global block"),()=>ConfirmGlobal(false),"RcGlobalRestore");
        blockButton.IsEnabled=restoreButton.IsEnabled=EngineMock&&MockEngine?.ReleaseManagement==true&&!GlobalBusy;
        var actions=new WrapPanel();foreach(var b in new[]{blockButton,restoreButton}){b.Margin=new Thickness(0,0,10,10);actions.Children.Add(b);}page.Children.Add(actions);
        if(!EngineMock)page.Children.Add(Actions((Loc.Pick("Tiltás megerősítésének előnézete","Preview block confirmation"),()=>ConfirmGlobal(true),"UatPreviewBlock"),(Loc.Pick("Feloldás megerősítésének előnézete","Preview restore confirmation"),()=>ConfirmGlobal(false),"UatPreviewRestore")));
        globalFeedback=Ui.Text(GlobalResult,14,"#FFD58A");AutomationProperties.SetAutomationId(globalFeedback,"RcGlobalResult");page.Children.Add(globalFeedback);
        page.Children.Add(Ui.Text(Loc.Pick("UAT: az éles globális írás külön jóváhagyásra vár. Az előnézet nem küld szabályt az Engine-nek.","UAT: live global writes await separate approval. Preview sends no rule to the Engine."),13,"#FFD58A"));
        page.Children.Add(EngineText(()=>Loc.Pick("Visszaolvasott globális tiltások: ","Read-back global blocks: ")+(EngineData.Fresh("/v2/policy")?string.Join(", ",Json.A(Json.P(EngineData.Value("/v2/policy"),"policy"),"globalBlockedDomains").Select(x=>x.GetString())):Unknown)));
    }
    void ConfirmGlobal(bool blocked)
    {
        var domain=DomainName.Normalize(globalDraft);if(domain.Length==0){GlobalResult=Loc.Pick("Adj meg érvényes domainnevet.","Enter a valid domain name.");if(globalFeedback!=null)globalFeedback.Text=GlobalResult;return;}
        if(!EngineMock){var locked=Ui.Button(Loc.Pick("Éles írás: engedélyezésre vár","Live writes await approval"),()=>{},"UatWriteLocked");locked.IsEnabled=false;Modal(Loc.Pick("Globális művelet – előnézet","Global action – preview"),Ui.Stack(Ui.Text((blocked?Loc.Pick("Globális tiltás: ","Global block: "):Loc.Pick("Globális tiltás eltávolítása: ","Remove global block: "))+domain),Ui.Text(Loc.Pick("Más otthoni eszközöket is érinthetne. Ez csak előnézet: nem történik írás. A szabály visszaolvasása sem bizonyítja minden kliens védelmét.","This could affect other home devices. This is preview only: no write occurs. Rule readback does not prove every client's protection.")),locked));return;}
        Modal(Loc.Pick("Globális művelet megerősítése","Confirm global action"),Ui.Stack(Ui.Text((blocked?Loc.Pick("Tiltás: ","Block: "):Loc.Pick("Globális tiltás eltávolítása: ","Remove global block: "))+domain),Ui.Text(Loc.Pick("Csak a helyi, szintetikus tesztmotor módosul. A visszaolvasás nem bizonyítja a teljes hálózat védelmét.","Only the local synthetic test engine changes. Readback does not prove network-wide protection.")),Actions((Loc.Pick("Megerősítés","Confirm"),async()=>{CloseModal();await ApplyGlobalDomain(domain,blocked);},"RcConfirmGlobal"),("Mégse",CloseModal,"RcCancelGlobal"))));
    }
    public async Task<GlobalDomainChange?> ApplyGlobalDomain(string domain,bool blocked)
    {
        if(!EngineMock)return null; // UAT hard read-only boundary: no flag or approval-file bypass.
        // A prototype role is never authority. Writes cannot target a live origin in this build.
        var mock=MockEngine;var poll=EnginePolling;
        if(GlobalBusy||!ReleaseCandidate||!EngineMode||!EngineMock||mock?.ReleaseManagement!=true||poll==null||!IPAddress.IsLoopback(IPAddress.Parse(new Uri(mock.Origin).Host)))return null;
        GlobalBusy=true;GlobalResult="Művelet folyamatban…";if(globalFeedback!=null)globalFeedback.Text=GlobalResult;if(blockButton!=null)blockButton.IsEnabled=false;if(restoreButton!=null)restoreButton.IsEnabled=false;
        GlobalDomainChange? result=null;
        try
        {
            var uri=new Uri(mock.Origin);var cfg=new DnsEngineConfig{Address=uri.Host,ManagementPort=uri.Port,TrustedCertificate=mock.Certificate,ApiToken=mock.Token};
            var service=new DnsEngineService(()=>new HttpClient(new HttpClientHandler{AllowAutoRedirect=false,UseProxy=false,UseCookies=false,ServerCertificateCustomValidationCallback=(_,cert,_,errors)=>HostsGuardian.Core.Services.ManagementSecurity.ValidateCertificate(cert,mock.Certificate,errors)}));
            await poll.RunExclusiveAsync(async cancellation=>{result=await service.SetGlobalDomainAsync(cfg,domain,blocked,cancellation);});
            GlobalResult=result!.Stored?(result.Applied?Loc.Pick("Szabály visszaigazolva; Engine-alkalmazási feltételek teljesülnek. A hálózati hatás nincs igazolva.","Rule confirmed; Engine application conditions satisfied. Network effect remains unverified."):Loc.Pick("Szabály eltárolva; alkalmazása nem igazolt.","Rule stored; application unconfirmed.")):Loc.Pick("A művelet nem igazolt. Ne tekintsd alkalmazottnak; ellenőrizd az adatforrást.","Operation unconfirmed. Do not treat it as applied; check the data source.");
            if(ReferenceEquals(poll,EnginePolling))await poll.PollOnceAsync();
        }
        catch(OperationCanceledException){GlobalResult=Loc.Pick("Művelet megszakítva; az eredmény nem igazolt.","Operation cancelled; outcome unconfirmed.");}
        catch{GlobalResult=Loc.Pick("Műveleti hiba; nincs igazolt eredmény.","Operation error; outcome unconfirmed.");}
        finally{GlobalBusy=false;if(globalFeedback!=null)globalFeedback.Text=GlobalResult;if(blockButton!=null)blockButton.IsEnabled=EngineMock;if(restoreButton!=null)restoreButton.IsEnabled=EngineMock;}
        return result;
    }
}
