namespace HostsGuardian.Core.Models;

public sealed class DeviceInfo
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Hostname { get; set; } = "";
    public bool IsOnline { get; set; }
    public int PingMs { get; set; } = -1;
}