using System;
using System.Net;
using System.Text;

namespace HostsGuardian.DnsEngine;

public static class DnsProtocol
{
    public readonly struct DnsQuestion
    {
        public DnsQuestion(string qName, ushort qType, ushort qClass, int questionEndOffset)
        {
            QName = qName;
            QType = qType;
            QClass = qClass;
            QuestionEndOffset = questionEndOffset;
        }

        public string QName { get; }
        public ushort QType { get; }
        public ushort QClass { get; }
        public int QuestionEndOffset { get; }
    }

    // Minimal DNS query parser (standard UDP query)
    public static bool TryParseQuestion(byte[] msg, out DnsQuestion q)
    {
        q = default;

        // DNS header is 12 bytes
        if (msg == null || msg.Length < 12) return false;

        // QDCOUNT
        var qdCount = ReadU16(msg, 4);
        if (qdCount < 1) return false;

        // question starts at offset 12
        var off = 12;

        // read QNAME as labels until 0
        var name = ReadQName(msg, ref off);
        if (string.IsNullOrWhiteSpace(name)) return false;

        // need QTYPE + QCLASS
        if (off + 4 > msg.Length) return false;

        var qtype = ReadU16(msg, off);
        var qclass = ReadU16(msg, off + 2);
        off += 4;

        q = new DnsQuestion(name, qtype, qclass, off);
        return true;
    }

    // Build a response that points to blockedIp:
    // - For A query: returns A record
    // - For AAAA query: returns empty answer but NXDOMAIN would be harsher
    // We do: A -> blockedIp, AAAA -> NOERROR with 0 answers (forces fallback to A on many clients)
    public static byte[] BuildBlockedResponse(byte[] request, DnsQuestion q, IPAddress blockedIp)
    {
        // Copy request to base response
        var resp = new byte[Math.Max(request.Length, q.QuestionEndOffset) + 16];
        Buffer.BlockCopy(request, 0, resp, 0, q.QuestionEndOffset);

        // Set flags: QR=1 (response), keep RD, set RA=1
        // request flags at 2..3
        // We take request flags, then force response bit + RA
        var flags = ReadU16(resp, 2);
        flags |= 0x8000; // QR
        flags |= 0x0080; // RA
        // clear TC
        flags &= unchecked((ushort)~0x0200);
        WriteU16(resp, 2, flags);

        // QDCOUNT stays 1
        WriteU16(resp, 4, 1);
        // All omitted sections must have zero counts, including the AAAA early-return path.
        WriteU16(resp, 6, 0);
        WriteU16(resp, 8, 0);
        WriteU16(resp, 10, 0);

        if (q.QType == 1 && q.QClass == 1) // IN A
        {
            // ANCOUNT = 1
            WriteU16(resp, 6, 1);
        }
        else
        {
            // Other blocked record types/classes return an empty answer.
            WriteU16(resp, 6, 0);
            // shrink to header+question only
            Array.Resize(ref resp, q.QuestionEndOffset);
            return resp;
        }

        var off = q.QuestionEndOffset;

        // Answer NAME: pointer to QNAME at 0x0C
        resp[off++] = 0xC0;
        resp[off++] = 0x0C;

        // TYPE A, CLASS IN
        WriteU16(resp, off, 1); off += 2;
        WriteU16(resp, off, 1); off += 2;

        // TTL
        WriteU32(resp, off, 60); off += 4;

        // RDLENGTH
        WriteU16(resp, off, 4); off += 2;

        // RDATA (IPv4)
        var ipBytes = blockedIp.GetAddressBytes();
        if (ipBytes.Length != 4) ipBytes = new byte[] { 0, 0, 0, 0 };

        resp[off++] = ipBytes[0];
        resp[off++] = ipBytes[1];
        resp[off++] = ipBytes[2];
        resp[off++] = ipBytes[3];

        Array.Resize(ref resp, off);
        return resp;
    }

    public static bool IsMatchingResponse(byte[] request, byte[] response)
    {
        if (request.Length < 12 || response.Length < 12 ||
            ReadU16(request, 0) != ReadU16(response, 0) ||
            (response[2] & 0x80) == 0 || (request[2] & 0x80) != 0 ||
            (request[2] & 0x78) != (response[2] & 0x78) ||
            ReadU16(request, 4) != 1 || ReadU16(response, 4) != 1 ||
            !TryParseQuestion(request, out var sent) || !TryParseQuestion(response, out var received))
            return false;
        if (!TryReadQuestionName(request, out var sentName) ||
            !TryReadQuestionName(response, out var receivedName) ||
            !sentName.SequenceEqual(receivedName) || sent.QType != received.QType || sent.QClass != received.QClass)
            return false;
        // TC explicitly reports an incomplete message. The forwarder classifies it separately.
        if ((response[2] & 2) != 0) return true;
        var offset = received.QuestionEndOffset;
        var records = ReadU16(response, 6) + ReadU16(response, 8) + ReadU16(response, 10);
        for (var record = 0; record < records; record++)
        {
            if (!TrySkipName(response, ref offset) || offset + 10 > response.Length) return false;
            var dataLength = ReadU16(response, offset + 8);
            offset += 10;
            if (offset + dataLength > response.Length) return false;
            offset += dataLength;
        }
        return offset == response.Length;
    }

    private static bool TryReadQuestionName(byte[] message, out byte[] identity, bool foldCase = true)
    {
        // Correlation uses label boundaries and wire octets, not lossy ASCII decoding.
        // Only ASCII A-Z are case-insensitive in DNS wire names.
        identity = Array.Empty<byte>();
        var labels = new List<byte>(255);
        var offset = 12;
        for (var steps = 0; steps < 128 && offset < message.Length; steps++)
        {
            var length = message[offset++];
            if (length == 0)
            {
                labels.Add(0);
                identity = labels.ToArray();
                return true;
            }
            if ((length & 0xc0) == 0xc0)
            {
                if (offset >= message.Length) return false;
                var pointer = ((length & 63) << 8) | message[offset++];
                if (pointer >= offset - 2) return false;
                offset = pointer;
                continue;
            }
            if (length > 63 || offset + length > message.Length || labels.Count + length + 2 > 255)
                return false;
            labels.Add(length);
            for (var index = 0; index < length; index++)
            {
                var value = message[offset++];
                labels.Add(foldCase && value is >= 65 and <= 90 ? (byte)(value + 32) : value);
            }
        }
        return false;
    }

    public static byte[] BuildServerFailure(byte[] request, DnsQuestion question)
    {
        // Re-encode the question so compressed requests never leave dangling pointers.
        if (!TryReadQuestionName(request, out var name, foldCase: false))
            throw new ArgumentException("Invalid request question", nameof(request));
        var response = new byte[12 + name.Length + 4];
        response[0] = request[0]; response[1] = request[1];
        WriteU16(response, 2, (ushort)(0x8082 | (ReadU16(request, 2) & 0x7910)));
        WriteU16(response, 4, 1);
        Buffer.BlockCopy(name, 0, response, 12, name.Length);
        var offset = 12 + name.Length;
        WriteU16(response, offset, question.QType);
        WriteU16(response, offset + 2, question.QClass);
        return response;
    }

    private static bool TrySkipName(byte[] message, ref int offset)
    {
        // Resource-record owner names may be the root (OPT), unlike domain questions.
        var nameOffset = offset;
        var wireLength = 1;
        var endOffset = -1;
        for (var steps = 0; steps < 128 && nameOffset < message.Length; steps++)
        {
            var length = message[nameOffset++];
            if (length == 0)
            {
                offset = endOffset >= 0 ? endOffset : nameOffset;
                return true;
            }
            if ((length & 0xc0) == 0xc0)
            {
                if (nameOffset >= message.Length) return false;
                var pointer = ((length & 63) << 8) | message[nameOffset++];
                if (pointer >= nameOffset - 2) return false;
                if (endOffset < 0) endOffset = nameOffset;
                nameOffset = pointer;
                continue;
            }
            if (length > 63 || nameOffset + length > message.Length) return false;
            wireLength += length + 1;
            if (wireLength > 255) return false;
            nameOffset += length;
        }
        return false;
    }

    private static string ReadQName(byte[] msg, ref int off)
    {
        // No compression expected in questions for typical clients,
        // but we handle pointer just in case.
        var sb = new StringBuilder();
        var jumped = false;
        var jumpOff = 0;
        var steps = 0;

        while (off < msg.Length)
        {
            if (steps++ > 128) return ""; // safety

            var len = msg[off++];

            if (len == 0)
            {
                if (jumped) off = jumpOff;
                return sb.ToString();
            }

            // pointer
            if ((len & 0xC0) == 0xC0)
            {
                if (off >= msg.Length) return "";
                var b2 = msg[off++];
                var ptr = ((len & 0x3F) << 8) | b2;
                if (ptr >= off - 2) return "";

                if (!jumped)
                {
                    jumpOff = off;
                    jumped = true;
                }

                off = ptr;
                continue;
            }

            if (len > 63 || off + len > msg.Length || sb.Length + len + 1 > 253) return "";

            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(msg, off, len));
            off += len;
        }

        return ""; // Unterminated/out-of-range names are malformed.
    }

    private static ushort ReadU16(byte[] b, int off)
        => (ushort)((b[off] << 8) | b[off + 1]);

    private static void WriteU16(byte[] b, int off, ushort v)
    {
        b[off] = (byte)(v >> 8);
        b[off + 1] = (byte)(v & 0xFF);
    }

    private static void WriteU32(byte[] b, int off, uint v)
    {
        b[off] = (byte)((v >> 24) & 0xFF);
        b[off + 1] = (byte)((v >> 16) & 0xFF);
        b[off + 2] = (byte)((v >> 8) & 0xFF);
        b[off + 3] = (byte)(v & 0xFF);
    }
}
