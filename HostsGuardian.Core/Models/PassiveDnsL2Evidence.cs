namespace HostsGuardian.Core.Models;

/// <summary>Ephemeral incoming Ethernet DNS claims; never permanent or authenticated identity.</summary>
public sealed record PassiveDnsL2Claim(string Address,string Mac,string Interface,
    DateTimeOffset ObservedAtUtc,DateTimeOffset ExpiresAtUtc);
public sealed record PassiveDnsL2Read(string RequestId,string Method,bool Complete,
    DateTimeOffset ReadAtUtc,string Reason,PassiveDnsL2Claim[] Evidence)
{
    public string? CaptureInstance { get; init; }
    public long InterfaceGeneration { get; init; }
    public string CaptureState { get; init; } = "Unknown";
    // No IPv6 claim is authorized by the current IPv4-only Ethernet parser.
    public string Ipv6IdentityState { get; init; } = "UnsupportedPassiveEvidence";
}
