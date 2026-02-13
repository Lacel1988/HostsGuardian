using System.Security.Principal;

namespace HostsGuardian.Core.Services;

public static class AdminService
{
    public static bool IsAdmin()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string CurrentUser()
    {
        return WindowsIdentity.GetCurrent().Name ?? "unknown";
    }
}
