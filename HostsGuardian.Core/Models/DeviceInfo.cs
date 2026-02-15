namespace HostsGuardian.Core.Models
{
    public sealed class DeviceInfo
    {
        public string Ip { get; set; } = "";
        public string Mac { get; set; } = "";
        public string Name { get; set; } = "";
        public string Type { get; set; } = "Unknown"; // PC, Mobile, TV, IoT
    }
}
