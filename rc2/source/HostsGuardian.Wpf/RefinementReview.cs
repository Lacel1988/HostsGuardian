namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
    public void ReviewNext(){if(ReviewMode)ShowRefinementScene(ReviewStep+1);}
    public void ShowRefinementScene(int scene)
    {
        ReviewStep=scene;ResetSessionClock();CloseModal();ExitStartup();SetReducedMotion(true);
        if(SessionState!="Active"||Account.Name!="admin.demo"){SignOut();DemoLogin("admin.demo","demo-only");}
        SetReducedMotion(false);ChangeLanguage(false);ChangeTheme(scene is 2 or 4 or 17 or 23 or 24);ActivityFiltersOpen=false;InsightHours=6;InsightDevice="";
        switch(scene)
        {
            case 1:case 2:case 15:Navigate("Security Insights");break;
            case 3:case 4:Navigate("Áttekintés");break;
            case 5:Navigate("Security Insights");ShowAnalystEvidence();break;
            case 6:InsightHours=12;InsightDevice="device-1";Navigate("Security Insights");break;
            case 7:case 23:Navigate("Domainek és policy");OpenPolicy("POL-YT-001");break;
            case 8:ActivitySearch="YouTube";Navigate("Tevékenység");break;
            case 9:case 24:ActivityFiltersOpen=true;ActivityUser="admin.demo";ActivitySearch="YouTube";Navigate("Tevékenység");break;
            case 10:SelectSettingsCategory("Megjelenés");break;
            case 11:SelectSettingsCategory("Felhasználók és jogosultságok");UserEditor(null);break;
            case 12:
                var user=Store.Accounts.FirstOrDefault(a=>a.Name=="visual.demo");if(user==null)Store.CreateAccount(Account,"visual.demo","Megfigyelő",out user);
                SelectSettingsCategory("Felhasználók és jogosultságok");UserEditor(user);break;
            case 13:SetReducedMotion(true);SignOut();DemoLogin("observer.demo","demo-only");OpenPolicy(null);break;
            case 14:Navigate("Áttekintés");AdvanceSessionClockForTest(TimeSpan.FromMinutes(6));break;
            case 16:case 17:SignOut();break;
            case 18:ShowBootstrapConcept();break;
            case 19:ShowActivationConcept();break;
            case 20:
                var admin=Account;var created=Store.Accounts.FirstOrDefault(a=>a.Name=="visual.operator");if(created==null)Store.CreateAccount(admin,"visual.operator","Kezelő",out created);
                SetReducedMotion(true);SignOut();DemoLogin("visual.operator","demo-only");Navigate("Domainek és policy");break;
            case 21:SelectSettingsCategory("Felhasználók és jogosultságok");break;
            case 22:SetReducedMotion(true);Navigate("Security Insights");break;
            default:ReviewStep=0;SignOut();break;
        }
        WriteStateReceipt();
    }
}

