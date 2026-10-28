using System.Collections.Immutable;
using System.Diagnostics;
using System.Threading.Channels;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public sealed record DnsDecisionObservation(DnsRequestContext Request, Guid? DeviceId, string IdentityState,
    string Domain, long? PolicyRevision, long MappingGeneration, bool Blocked, string Reason)
{
    public ImmutableArray<DecisionEvidence> DecisionChain { get; init; } = [];
    public bool EvidenceTruncated { get; init; }
    public Guid CorrelationId => Request.CorrelationId;
    public ushort QueryType { get; init; }
    public long Sequence { get; init; }
    public long MonotonicTimestamp { get; init; }
    public string ResponseState { get; init; } = "DecisionOnly";
    public int? ResponseCode { get; init; }
    public int ResponseBytes { get; init; }
    public double? ProcessingMilliseconds { get; init; }
    public double? TransportMilliseconds { get; init; }
}

/// <summary>Bounded diagnostic evidence of actual received DNS requests, never identity discovery.</summary>
public sealed class DnsObservationStore(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly object _gate = new();
    public const int Capacity = 2048;
    public const int QueueCapacity = 512;
    private readonly Queue<Guid> _recent = new();
    private readonly Dictionary<Guid,DnsDecisionObservation> _rows = new();
    private readonly Channel<Action> _events = Channel.CreateBounded<Action>(new BoundedChannelOptions(QueueCapacity)
        { FullMode = BoundedChannelFullMode.Wait, SingleReader = false, SingleWriter = false, AllowSynchronousContinuations = false });
    private long _dropped, _evicted, _sequence;
    private int _draining;
    public long Dropped => Interlocked.Read(ref _dropped);
    public long Evicted => Interlocked.Read(ref _evicted);
    private void Enqueue(Action action)
    {
        // Receive path never waits for telemetry or disk. Overflow is visible.
        if (!_events.Writer.TryWrite(action)) { Interlocked.Increment(ref _dropped); return; }
        if (Interlocked.CompareExchange(ref _draining, 1, 0) == 0) _ = Task.Run(DrainWorker);
    }
    private void DrainWorker()
    {
        try { Drain(); }
        finally {
            Interlocked.Exchange(ref _draining, 0);
            if (_events.Reader.TryPeek(out _) && Interlocked.CompareExchange(ref _draining, 1, 0) == 0) _ = Task.Run(DrainWorker);
        }
    }
    private void Drain()
    {
        lock (_gate) {
            Purge();
            for (var n = 0; n < QueueCapacity && _events.Reader.TryRead(out var action); n++) {
                try { action(); } catch { Interlocked.Increment(ref _dropped); }
            }
        }
    }
    public void Record(DnsRequestContext context, EffectivePolicyExplanation decision, ushort queryType = 0)
    {
        var timestamp = _time.GetTimestamp();
        var observation = new DnsDecisionObservation(context, decision.DeviceId, decision.IdentityState, decision.Domain,
                decision.Revision, decision.MappingGeneration, decision.Blocked, decision.Reason)
            { DecisionChain = decision.DecisionChain.Take(4).ToImmutableArray(), EvidenceTruncated = decision.DecisionChain.Length > 4,
              QueryType = queryType, MonotonicTimestamp = timestamp };
        Enqueue(() =>
        {
            if (_rows.ContainsKey(context.CorrelationId)) return;
            if (Expired(observation)) { Interlocked.Increment(ref _evicted); return; }
            if (_recent.Count == Capacity) { _rows.Remove(_recent.Dequeue()); Interlocked.Increment(ref _evicted); }
            _recent.Enqueue(context.CorrelationId);
            _rows[context.CorrelationId] = observation with { Sequence = ++_sequence };
        });
    }
    public void Complete(DnsRequestContext context, string state, byte[]? response, double milliseconds)
    {
        if (state is not ("ResponsePrepared" or "TransportWriteSucceeded" or "TransportWriteFailed" or "Cancelled")) return;
        var code = response is { Length: >= 12 } ? response[3] & 15 : (int?)null;
        var size = response?.Length ?? 0;
        Enqueue(() => {
            if (!_rows.TryGetValue(context.CorrelationId,out var item)) return;
            _rows[context.CorrelationId] = item with {
                ResponseState = state, ResponseCode = code ?? item.ResponseCode,
                ResponseBytes = size == 0 ? item.ResponseBytes : size,
                ProcessingMilliseconds = state == "ResponsePrepared" ? milliseconds : item.ProcessingMilliseconds,
                TransportMilliseconds = state == "ResponsePrepared" ? item.TransportMilliseconds : milliseconds };
        });
    }
    // Timestamp acquisition and enqueue order can differ across producers. FIFO is eviction order,
    // not expiry order. Bounded scan runs on the consumer/read path, never on DNS producers.
    private bool Expired(DnsDecisionObservation item) {
        var age=_time.GetElapsedTime(item.MonotonicTimestamp);
        return age<TimeSpan.Zero || age>=TimeSpan.FromMinutes(15);
    }
    private void Purge() {
        var count=_recent.Count;
        for(var n=0;n<count;n++) {
            var id=_recent.Dequeue();
            if(Expired(_rows[id])) { _rows.Remove(id);Interlocked.Increment(ref _evicted); }
            else _recent.Enqueue(id);
        }
    }
    public DnsDecisionObservation[] Read() { Drain(); lock (_gate) { Purge(); return _recent.Select(id=>_rows[id]).ToArray(); } }
}
