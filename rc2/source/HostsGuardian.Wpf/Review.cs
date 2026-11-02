using System.Windows.Input;
namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
    public bool ReviewMode {get;set;}
    public int ReviewStep {get;private set;}
    public void ReviewNextV23()
    {
        if(!ReviewMode)return;
        ReviewStep++;CloseModal();ExitStartup();
        switch(ReviewStep)
        {
            case 1:ChangeTheme(true);break;
            case 2:SetReducedMotion(true);DemoLogin("admin.demo","demo-only");SetReducedMotion(false);StartStartup(10);AdvanceStartupPhase();AdvanceStartupPhase();AdvanceStartupPhase();break;
            case 3:ChangeTheme(false);Navigate("Áttekintés");break;
            case 4:ChangeTheme(true);Navigate("Áttekintés");break;
            case 5:ChangeTheme(false);Navigate("Eszközök");break;
            case 6:ExpandDevice("device-1");break;
            case 7:Navigate("Domainek és policy");break;
            case 8:OpenPolicy("POL-YT-001");break;
            case 9:ShowImpact(Store.Policies[0].Copy(),Store.Policies[0].Id);break;
            case 10:Navigate("Security Insights");break;
            case 11:Navigate("Diagnosztika");break;
            case 12:ActivitySearch="YouTube";Navigate("Tevékenység");break;
            case 13:SettingsTab="Biztonság és hozzáférés";Navigate("Beállítások");break;
            case 14:SettingsTab="Nyelv";BuildPage();break;
            case 15:SettingsTab="Megjelenés";BuildPage();break;
            case 16:SettingsTab="Felhasználók és jogosultságok";BuildPage();break;
            case 17:ChangeLanguage(true);Navigate("Security Insights");break;
            case 18:SetReducedMotion(true);SettingsTab="Megjelenés";Navigate("Beállítások");break;
            case 19:ChangeTheme(true);Navigate("Domainek és policy");break;
            case 20:ShowLogin(true);break;
            default:ReviewStep=0;ChangeLanguage(false);ChangeTheme(false);SignOut();break;
        }
        WriteStateReceipt();
    }
}

