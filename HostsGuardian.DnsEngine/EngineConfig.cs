namespace HostsGuardian.DnsEngine;

public sealed class EngineConfig
{
    // Production DNS port for UDP and the planned TCP listener.
    public int DnsListenPort { get; set; } = 53;
    public bool EnableIpv6Dns { get; set; } = true;
    public string UpstreamDnsIpv4 { get; set; } = "1.1.1.1";
    public int UpstreamDnsPort { get; set; } = 53;
    public string BlockedIpv4 { get; set; } = "0.0.0.0";
    public int UpstreamTimeoutMs { get; set; } = 2500;
    public int UpstreamRetryCount { get; set; } = 1;
    public string FallbackDnsIpv4 { get; set; } = "";
    public int FallbackDnsPort { get; set; } = 53;
    public int MaxConcurrentUdpRequests { get; set; } = 16;
    public string PolicyFilePath { get; set; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HostsGuardian.DnsEngine", "policy.json");

    public string ApiBindIp { get; set; } = "127.0.0.1";
    public int ApiPort { get; set; } = 3000;
    public string CredentialPath { get; set; } = "";
    public string CertificatePath { get; set; } = "";
    public string CertificateKeyPath { get; set; } = "";
}
