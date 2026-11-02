using System.Net;
namespace HostsGuardian.Core.Services;
public static class ObservationNotificationKey
{
    public static string Create(string mac,string address)
    {
        var normalized=DevicePolicyIdentity.NormalizeMac(mac);
        return "unknown."+(normalized!=""?normalized:IPAddress.TryParse(address,out var ip)?ip.ToString():"unresolved");
    }
}
