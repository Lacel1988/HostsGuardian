using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HostsGuardian.Core.Services
{
    public sealed class DnsProxyService
    {
        public sealed class DnsLogItem
        {
            public DateTime AtUtc { get; set; } = DateTime.UtcNow;
            public string ClientIp { get; set; } = "";
            public string Domain { get; set; } = "";
            public bool Blocked { get; set; }
        }

        private readonly object _lock = new();
        private UdpClient? _udp;
        private CancellationTokenSource? _cts;

        public bool IsRunning { get; private set; }
        public int ListenPort { get; private set; } = 5300;

        public IPEndPoint Upstream { get; set; } = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);

        // globális block lista
        public List<string> BlockedDomains { get; set; } = new();

        // per-device block lista: kulcs = client IP string
        public Dictionary<string, List<string>> BlockedByClientIp { get; set; } = new();

        public event Action<DnsLogItem>? OnLog;

        public void Start(int port = 5300)
        {
            lock (_lock)
            {
                if (IsRunning) return;

                ListenPort = port;
                _cts = new CancellationTokenSource();
                _udp = new UdpClient(port);
                IsRunning = true;

                _ = Task.Run(() => Loop(_cts.Token));
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!IsRunning) return;

                try { _cts?.Cancel(); } catch { }
                try { _udp?.Close(); } catch { }
                try { _udp?.Dispose(); } catch { }

                _udp = null;
                _cts = null;
                IsRunning = false;
            }
        }

        private async Task Loop(CancellationToken ct)
        {
            if (_udp == null) return;

            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult recv;
                try
                {
                    recv = await _udp.ReceiveAsync(ct);
                }
                catch
                {
                    if (ct.IsCancellationRequested) break;
                    continue;
                }

                _ = Task.Run(async () =>
                {
                    await HandlePacket(recv, ct);
                }, ct);
            }
        }

        private async Task HandlePacket(UdpReceiveResult recv, CancellationToken ct)
        {
            if (_udp == null) return;

            var clientIp = recv.RemoteEndPoint.Address.ToString();
            var domain = TryParseQname(recv.Buffer) ?? "";
            var blocked = IsBlocked(clientIp, domain);

            try
            {
                OnLog?.Invoke(new DnsLogItem
                {
                    AtUtc = DateTime.UtcNow,
                    ClientIp = clientIp,
                    Domain = domain,
                    Blocked = blocked
                });
            }
            catch { }

            if (blocked)
            {
                // NXDOMAIN válasz
                var resp = BuildNxDomainResponse(recv.Buffer);
                if (resp != null)
                {
                    try { await _udp.SendAsync(resp, resp.Length, recv.RemoteEndPoint); } catch { }
                }
                return;
            }

            // forward upstream
            byte[] upstreamResp;
            try
            {
                upstreamResp = await QueryUpstream(recv.Buffer, ct);
            }
            catch
            {
                // ha upstream fail, NXDOMAIN helyett inkább “SERVFAIL” is lehetne,
                // de most legyen NXDOMAIN-szerű minimal
                var resp = BuildServFailResponse(recv.Buffer);
                if (resp != null)
                {
                    try { await _udp.SendAsync(resp, resp.Length, recv.RemoteEndPoint); } catch { }
                }
                return;
            }

            try { await _udp.SendAsync(upstreamResp, upstreamResp.Length, recv.RemoteEndPoint); } catch { }
        }

        private bool IsBlocked(string clientIp, string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;

            var d = domain.Trim().Trim('.').ToLowerInvariant();

            // per-client block
            if (BlockedByClientIp.TryGetValue(clientIp, out var per) && per != null)
            {
                if (per.Any(x => DomainMatch(d, x))) return true;
            }

            // global block
            if (BlockedDomains.Any(x => DomainMatch(d, x))) return true;

            return false;
        }

        private static bool DomainMatch(string domain, string rule)
        {
            var r = (rule ?? "").Trim().Trim('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(r)) return false;

            if (domain == r) return true;
            if (domain.EndsWith("." + r)) return true; // subdomain tiltás
            return false;
        }

        private async Task<byte[]> QueryUpstream(byte[] query, CancellationToken ct)
        {
            using var c = new UdpClient();
            c.Client.ReceiveTimeout = 2000;
            c.Client.SendTimeout = 2000;

            await c.SendAsync(query, query.Length, Upstream);
            var recv = await c.ReceiveAsync(ct);
            return recv.Buffer;
        }

        // DNS QNAME parse (nagyon célzott, de elég a kérdések 99%-ához)
        private static string? TryParseQname(byte[] packet)
        {
            try
            {
                if (packet.Length < 12) return null;
                int pos = 12;

                // QNAME: label1len label1 label2len label2 ... 0
                var parts = new List<string>();
                while (pos < packet.Length)
                {
                    byte len = packet[pos++];
                    if (len == 0) break;
                    if (len > 63) return null; // compression not expected in question typically

                    if (pos + len > packet.Length) return null;
                    var label = System.Text.Encoding.ASCII.GetString(packet, pos, len);
                    parts.Add(label);
                    pos += len;
                }

                if (parts.Count == 0) return null;
                return string.Join(".", parts);
            }
            catch
            {
                return null;
            }
        }

        // NXDOMAIN: rcode=3, ancount=0
        private static byte[]? BuildNxDomainResponse(byte[] query)
        {
            return BuildErrorResponse(query, rcode: 3);
        }

        // SERVFAIL: rcode=2
        private static byte[]? BuildServFailResponse(byte[] query)
        {
            return BuildErrorResponse(query, rcode: 2);
        }

        private static byte[]? BuildErrorResponse(byte[] query, int rcode)
        {
            try
            {
                if (query.Length < 12) return null;

                // Másoljuk az egész kérdést válasznak, majd header fix
                var resp = (byte[])query.Clone();

                // Flags: QR=1 (response), copy RD, set RA=1, set RCODE
                // query flags = bytes 2-3
                ushort flags = (ushort)((resp[2] << 8) | resp[3]);

                // QR
                flags |= 0x8000;

                // RA
                flags |= 0x0080;

                // RCODE set
                flags &= 0xFFF0;
                flags |= (ushort)(rcode & 0x000F);

                resp[2] = (byte)(flags >> 8);
                resp[3] = (byte)(flags & 0xFF);

                // ANCOUNT, NSCOUNT, ARCOUNT = 0
                resp[6] = 0; resp[7] = 0;
                resp[8] = 0; resp[9] = 0;
                resp[10] = 0; resp[11] = 0;

                return resp;
            }
            catch
            {
                return null;
            }
        }
    }
}
