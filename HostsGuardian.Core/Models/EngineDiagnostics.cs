namespace HostsGuardian.Core.Models;

// Versioned, transport-neutral contracts. No domains, clients, credentials or policy bodies.
public sealed record DnsCounters(long Received, long Udp, long Tcp, long Allowed, long PolicyBlocked,
    long Failed, long Rejected, long CapacityDropped, long Cancelled, long Servfail,
    long UpstreamAttempts, long UpstreamTimeouts, long UpstreamFailures, long UpstreamRetries,
    long FallbackAttempts, long TcpConnectionsRejected, long TransportFailures)
{ public long Completed => Allowed + PolicyBlocked + Failed + Rejected + Cancelled; }
public sealed record LatencySummary(int Samples, double? RecentMs, double? P50Ms, double? P95Ms, long Skipped);
public sealed record ResolverDiagnostics(string Address, long Attempts, long Timeouts, long Failures,
    long Retries, long FallbackAttempts, LatencySummary Latency, string State);
public sealed record EnginePressure(int CurrentRequests, int PeakRequests, int UdpCurrent, int UdpCapacity,
    int TcpCurrentRequests, int TcpConnections, int TcpConnectionCapacity, long CapacityDrops);
public sealed record EngineResources(double UptimeSeconds, double? CpuPercent, long? WorkingSetBytes,
    int ProcessId, DateTimeOffset StartedAtUtc, string Revision);
public sealed record HealthComponent(string Component, string State, string? IncidentId, DateTimeOffset? SinceUtc);
public sealed record OperationalEvent(long Sequence, string InstanceId, string IncidentId, string Component,
    string Type, string Severity, DateTimeOffset OccurredAtUtc, string State, string SummaryId, string? RecoveryOf);
public sealed record OperationalEventBatch(int SchemaVersion, string InstanceId, long LatestSequence,
    bool CursorGap, OperationalEvent[] Events, HealthComponent[] Components);
public sealed record EngineDiagnosticsSnapshot(int SchemaVersion, string InstanceId, DateTimeOffset SnapshotUtc,
    DnsCounters Counters, EnginePressure Pressure, LatencySummary UpstreamLatency,
    LatencySummary ProcessingLatency, ResolverDiagnostics[] Resolvers, EngineResources Resources,
    string Health, HealthComponent[] Components);
