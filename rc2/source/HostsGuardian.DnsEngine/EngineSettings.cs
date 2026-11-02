using System.Net;
using System.Net.Sockets;

namespace HostsGuardian.DnsEngine;

/// <summary>A validated startup snapshot. Mutable input configuration is not used by runtime components.</summary>
public sealed record EngineSettings(
    int DnsPort, IPAddress UpstreamAddress, int UpstreamPort, IPAddress BlockedAddress,
    int UpstreamTimeoutMs, IPAddress ApiAddress, int ApiPort,
    string CredentialPath, string CertificatePath, string CertificateKeyPath)
{
    public bool EnableIpv6Dns { get; init; } = true;
    public string PolicyFilePath { get; init; } = "";
    public int UpstreamRetryCount { get; init; } = 1;
    public IPEndPoint? FallbackEndpoint { get; init; }
    public int MaxConcurrentUdpRequests { get; init; } = 16;
    public static EngineSettings FromConfig(EngineConfig config)
    {
        ValidatePort(config.DnsListenPort, "DNS");
        ValidatePort(config.UpstreamDnsPort, "upstream DNS");
        ValidatePort(config.ApiPort, "management API");
        var upstream = ParseIpv4(config.UpstreamDnsIpv4, "upstream DNS");
        var blocked = ParseIpv4(config.BlockedIpv4, "blocked response");
        if (!IPAddress.TryParse(config.ApiBindIp, out var apiAddress))
            throw new InvalidOperationException("Invalid management binding address");
        if (config.UpstreamTimeoutMs is < 10 or > 10000)
            throw new InvalidOperationException("Invalid upstream timeout");
        if (config.UpstreamRetryCount is < 0 or > 2)
            throw new InvalidOperationException("Invalid upstream retry count");
        if (config.MaxConcurrentUdpRequests is < 1 or > 64)
            throw new InvalidOperationException("Invalid UDP concurrency limit");
        ValidatePort(config.FallbackDnsPort, "fallback DNS");
        IPEndPoint? fallback = null;
        if (config.FallbackDnsIpv4 != "")
        {
            fallback = new IPEndPoint(ParseIpv4(config.FallbackDnsIpv4, "fallback DNS"), config.FallbackDnsPort);
            if (fallback.Address.Equals(upstream) && fallback.Port == config.UpstreamDnsPort)
                throw new InvalidOperationException("Fallback must differ from primary upstream");
        }
        return new EngineSettings(config.DnsListenPort, upstream, config.UpstreamDnsPort,
            blocked, config.UpstreamTimeoutMs, apiAddress, config.ApiPort,
            config.CredentialPath, config.CertificatePath, config.CertificateKeyPath)
        {
            EnableIpv6Dns = config.EnableIpv6Dns,
            PolicyFilePath = Path.GetFullPath(config.PolicyFilePath),
            UpstreamRetryCount = config.UpstreamRetryCount,
            FallbackEndpoint = fallback,
            MaxConcurrentUdpRequests = config.MaxConcurrentUdpRequests
        };
    }

    private static void ValidatePort(int port, string component)
    {
        if (port is < 1 or > 65535)
            throw new InvalidOperationException($"Invalid {component} port");
    }

    private static IPAddress ParseIpv4(string value, string component)
    {
        if (!IPAddress.TryParse(value, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException($"Invalid {component} IPv4 address");
        return address;
    }
}
