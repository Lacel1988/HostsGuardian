using System.Collections.Generic;

namespace HostsGuardian.Wpf.Models
{
    public sealed class RouterDetectionResult
    {
        public string InterfaceName { get; set; } = "";
        public string LocalIp { get; set; } = "";
        public string GatewayIp { get; set; } = "";
        public string DnsServers { get; set; } = "";
        public string WifiSsid { get; set; } = "";

        public List<RouterCandidate> Candidates { get; set; } = new();
        public string Notes { get; set; } = "";
    }
}
