using System.IO;
using System.Windows;
using System.Windows.Controls;
using DesignPrototype.Engine;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
 string uatConnectionNotice="";
 internal async Task ConnectUat()=>await EndEngineSession("Új Engine-hitelesítés szükséges.");
 void UatSettingsPage()=>IntegratedSettings();
 internal void UatPreview(bool blocked)=>ConfirmGlobal(blocked);
 internal void UatSetDomain(string domain){globalDraft=domain;}
 internal bool UatBindingsMatch()=>engineTexts.Count>0&&engineTexts.All(x=>x.Text.Text==x.Value());
 internal bool UatNoLogin=>loginOverlay==null;
 internal bool UatHasSourcePlaceholder=>!EngineMode&&EngineData.Devices.Count==0;
 internal ScrollViewer UatMainScroll=>mainScroll;
 internal async Task AttachUatTestReader(EngineReader reader){await StopEngine();EngineMock=false;await AttachEngine(reader,20,false);}
 internal void CheckUatOfflineLabels(string output)
 {
  Directory.CreateDirectory(output);var rows=new List<object>();foreach(bool en in new[]{true,false}){ChangeLanguage(en);rows.Add(new{english=en,label=Convert.ToString(scenarioButton.Content),pass=Convert.ToString(scenarioButton.Content)!.StartsWith("UAT")&&!EngineMode});}
  File.WriteAllText(Path.Combine(output,"offline-labels.json"),System.Text.Json.JsonSerializer.Serialize(rows,new System.Text.Json.JsonSerializerOptions{WriteIndented=true}));
 }
}

