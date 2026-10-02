using System.Buffers.Binary;

namespace HostsGuardian.DnsEngine;

/// <summary>DNS-over-TCP message framing only; the two-byte prefix is not part of the DNS payload.</summary>
public static class TcpDnsFraming
{
    public const int MaximumMessageLength = ushort.MaxValue;
    private const int MinimumMessageLength = 12;

    public static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = new byte[2];
        var firstByte = await stream.ReadAsync(prefix.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        if (firstByte == 0) return null; // Clean disconnect between messages.
        await stream.ReadExactlyAsync(prefix.AsMemory(1, 1), cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        if (length < MinimumMessageLength) throw new InvalidDataException("Unsupported DNS frame length");
        var payload = new byte[length]; // At most 65,535 bytes, regardless of peer input.
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    public static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length is < MinimumMessageLength or > MaximumMessageLength)
            throw new InvalidDataException("Unsupported DNS response length");
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)payload.Length);
        // NetworkStream.WriteAsync sends the complete supplied memory; it handles partial socket writes.
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }
}
