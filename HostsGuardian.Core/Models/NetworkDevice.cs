namespace HostsGuardian.Core.Models
{
    public sealed class NetworkDevice
    {
        public string Ip { get; set; } = "";
        public string Mac { get; set; } = "";      // "AA:BB:CC:DD:EE:FF"
        public string Hostname { get; set; } = ""; // ha tudjuk
        public string IdentityEvidence { get; set; } = "";
        public string VendorHint { get; set; } = "";

        // Scan meta
        public bool IsGatewayCandidate { get; set; }
        public string Notes { get; set; } = "";
    }
}
