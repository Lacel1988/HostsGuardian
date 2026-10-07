using System.Net;
namespace HostsGuardian.DnsEngine;

public enum DnsTransport { Udp, Tcp }
/// <summary>Packet identity, never MAC or durable device identity. Port is diagnostic only.</summary>
public sealed record DnsRequestContext(DnsTransport Transport, string SourceAddress, int SourcePort,
    DateTimeOffset ReceivedAtUtc, string? NetworkScope)
{
    public static DnsRequestContext From(DnsTransport transport, IPEndPoint peer, DateTimeOffset receivedAtUtc,
        string? networkScope = null) => new(transport, (peer.Address.IsIPv4MappedToIPv6 ? peer.Address.MapToIPv4() : peer.Address).ToString(), peer.Port, receivedAtUtc, networkScope);
}
