using System.Diagnostics;
using System.Net;
using HostsGuardian.Core.Models;

namespace HostsGuardian.DnsEngine;

/// <summary>Eight fixed shards: latency writes never wait for another query or API reader.</summary>
public sealed class RollingLatency
{
    public const int WindowSeconds = 60;
    public const int MaximumSamples = 2048;
    private sealed class Shard { public readonly object Gate = new(); public readonly double[] Values = new double[256];
        public readonly long[] Times = new long[256]; public readonly long[] Sequence = new long[256]; public int Next; }
    private readonly Shard[] _shards = Enumerable.Range(0, 8).Select(_ => new Shard()).ToArray();
    private long _skipped, _sequence;
    public void Record(double milliseconds, long timestamp = 0)
    {
        if (!double.IsFinite(milliseconds) || milliseconds < 0) return;
        var shard = _shards[Environment.CurrentManagedThreadId & 7];
        if (!Monitor.TryEnter(shard.Gate)) { Interlocked.Increment(ref _skipped); return; }
        try { var i = shard.Next++ & 255; shard.Values[i] = milliseconds;
            shard.Times[i] = timestamp == 0 ? Stopwatch.GetTimestamp() : timestamp; shard.Sequence[i] = Interlocked.Increment(ref _sequence); }
        finally { Monitor.Exit(shard.Gate); }
    }
    public LatencySummary Snapshot(long now = 0)
    {
        if (now == 0) now = Stopwatch.GetTimestamp();
        var cutoff = now - WindowSeconds * Stopwatch.Frequency;
        var values = new double[MaximumSamples]; var count = 0; long latest = 0, latestSequence = 0; double? recent = null;
        foreach (var shard in _shards) lock (shard.Gate)
            for (var i = 0; i < 256; i++)
                if (shard.Times[i] > 0 && shard.Times[i] >= cutoff && shard.Times[i] <= now)
                { values[count++] = shard.Values[i]; if (shard.Times[i] > latest || (shard.Times[i] == latest && shard.Sequence[i] > latestSequence)) { latest = shard.Times[i]; latestSequence = shard.Sequence[i]; recent = shard.Values[i]; } }
        Array.Sort(values, 0, count);
        return new(count, recent, count == 0 ? null : values[(int)Math.Ceiling(count * .5) - 1],
            count == 0 ? null : values[(int)Math.Ceiling(count * .95) - 1], Interlocked.Read(ref _skipped));
    }
}

public sealed class DnsTelemetry
{
    public DeviceDnsDiagnosticsStore Devices { get; } = new();
    private long _udp, _tcp, _allowed, _blocked, _failed, _rejected, _drops, _cancelled, _servfail;
    private long _attempts, _timeouts, _upstreamFailures, _retries, _fallback, _tcpRejected, _transportFailures;
    private int _current, _peak, _udpCurrent, _tcpCurrent, _connections;
    private sealed class Resolver
    { public required string Address; public long Attempts, Timeouts, Failures, Retries, Fallback, LastAt; public int LastOutcome; public readonly RollingLatency Latency = new(); }
    private readonly Resolver[] _resolvers;
    public RollingLatency UpstreamLatency { get; } = new();
    public RollingLatency ProcessingLatency { get; } = new();
    public int UdpCapacity { get; }
    public DnsTelemetry(EngineSettings settings)
    {
        UdpCapacity = settings.MaxConcurrentUdpRequests;
        _resolvers = settings.FallbackEndpoint == null
            ? [new() { Address = new IPEndPoint(settings.UpstreamAddress, settings.UpstreamPort).ToString() }]
            : [new() { Address = new IPEndPoint(settings.UpstreamAddress, settings.UpstreamPort).ToString() }, new() { Address = settings.FallbackEndpoint.ToString() }];
    }
    public void Received(DnsTransport transport)
    { if (transport == DnsTransport.Udp) Interlocked.Increment(ref _udp); else Interlocked.Increment(ref _tcp); }
    public void Enter(DnsTransport transport)
    {
        var current = Interlocked.Increment(ref _current); int peak;
        do { peak = Volatile.Read(ref _peak); if (peak >= current) break; } while (Interlocked.CompareExchange(ref _peak, current, peak) != peak);
        if (transport == DnsTransport.Udp) Interlocked.Increment(ref _udpCurrent); else Interlocked.Increment(ref _tcpCurrent);
    }
    public void Exit(DnsTransport transport)
    { if (transport == DnsTransport.Udp) Interlocked.Decrement(ref _udpCurrent); else Interlocked.Decrement(ref _tcpCurrent); Interlocked.Decrement(ref _current); }
    public void Allowed() => Interlocked.Increment(ref _allowed);
    public void Blocked() => Interlocked.Increment(ref _blocked);
    public void Failed(bool servfail = true) { if (servfail) Interlocked.Increment(ref _servfail); else Interlocked.Increment(ref _failed); }
    public void Rejected(bool capacity = false) { if (capacity) Interlocked.Increment(ref _drops); else Interlocked.Increment(ref _rejected); }
    public void Cancelled() => Interlocked.Increment(ref _cancelled);
    public void TransportFailed() => Interlocked.Increment(ref _transportFailures);
    public void Connection(bool entering) { if (entering) Interlocked.Increment(ref _connections); else Interlocked.Decrement(ref _connections); }
    public void RejectConnection() => Interlocked.Increment(ref _tcpRejected);
    public void Attempt(int resolverIndex, UpstreamOutcome outcome, double elapsedMs, bool retry, bool fallback)
    {
        var resolver = _resolvers[resolverIndex];
        Interlocked.Increment(ref _attempts); Interlocked.Increment(ref resolver.Attempts);
        Volatile.Write(ref resolver.LastOutcome, (int)outcome); Interlocked.Exchange(ref resolver.LastAt, Stopwatch.GetTimestamp());
        if (retry) { Interlocked.Increment(ref _retries); Interlocked.Increment(ref resolver.Retries); }
        if (fallback) { Interlocked.Increment(ref _fallback); Interlocked.Increment(ref resolver.Fallback); }
        if (outcome == UpstreamOutcome.Timeout) { Interlocked.Increment(ref _timeouts); Interlocked.Increment(ref resolver.Timeouts); }
        if (outcome is not (UpstreamOutcome.Response or UpstreamOutcome.Truncated or UpstreamOutcome.Cancelled))
        { Interlocked.Increment(ref _upstreamFailures); Interlocked.Increment(ref resolver.Failures); }
        if (outcome is UpstreamOutcome.Response or UpstreamOutcome.Truncated)
        { UpstreamLatency.Record(elapsedMs); resolver.Latency.Record(elapsedMs); }
    }
    public DnsCounters Counters()
    {
        // Exclusive outcome sums and received transport sum are exact; started parent counters read last.
        // Other fields are adjacent-in-time observations, without freezing DNS workers.
        var drops = Interlocked.Read(ref _drops); var servfail = Interlocked.Read(ref _servfail);
        var allowed = Interlocked.Read(ref _allowed); var blocked = Interlocked.Read(ref _blocked); var failed = servfail + Interlocked.Read(ref _failed);
        var rejected = drops + Interlocked.Read(ref _rejected); var cancelled = Interlocked.Read(ref _cancelled);
        var timeouts = Interlocked.Read(ref _timeouts); var upstreamFailures = Interlocked.Read(ref _upstreamFailures);
        var retries = Interlocked.Read(ref _retries); var fallback = Interlocked.Read(ref _fallback); var attempts = Interlocked.Read(ref _attempts);
        var udp = Interlocked.Read(ref _udp); var tcp = Interlocked.Read(ref _tcp);
        return new(udp + tcp, udp, tcp, allowed, blocked, failed, rejected, drops, cancelled, servfail,
            attempts, timeouts, upstreamFailures, retries, fallback, Interlocked.Read(ref _tcpRejected), Interlocked.Read(ref _transportFailures));
    }
    public EnginePressure Pressure() => new(Volatile.Read(ref _current), Volatile.Read(ref _peak), Volatile.Read(ref _udpCurrent), UdpCapacity,
        Volatile.Read(ref _tcpCurrent), Volatile.Read(ref _connections), TcpDnsServer.MaximumConnections, Interlocked.Read(ref _drops));
    private static string ResolverState(Resolver resolver)
    {
        var at = Interlocked.Read(ref resolver.LastAt);
        if (at == 0 || Stopwatch.GetElapsedTime(at).TotalSeconds > RollingLatency.WindowSeconds) return "NotMeasured";
        return (UpstreamOutcome)Volatile.Read(ref resolver.LastOutcome) switch
        { UpstreamOutcome.Response or UpstreamOutcome.Truncated => "RecentSuccess", UpstreamOutcome.Cancelled => "Cancelled", _ => "RecentFailure" };
    }
    public ResolverDiagnostics[] Resolvers() => _resolvers.Select(r => new ResolverDiagnostics(r.Address,
        Interlocked.Read(ref r.Attempts), Interlocked.Read(ref r.Timeouts), Interlocked.Read(ref r.Failures),
        Interlocked.Read(ref r.Retries), Interlocked.Read(ref r.Fallback), r.Latency.Snapshot(), ResolverState(r))).ToArray();
}
