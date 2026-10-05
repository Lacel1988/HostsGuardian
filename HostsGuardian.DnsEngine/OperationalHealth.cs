using System.Diagnostics;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public sealed record HealthDefaults(int WindowSeconds = 30, int TriggerSeconds = 15, int CriticalSeconds = 30,
    int RecoverySeconds = 30, int MinimumObservations = 10, double FailureRatio = .2,
    double CriticalFailureRatio = .5, double RecoveryFailureRatio = .05,
    double SlowP95Ms = 500, double RecoveryP95Ms = 300, int EventCapacity = 64);

/// <summary>Engine-owned persisted-in-time states; bounded in-memory incidents, independent of viewers.</summary>
public sealed class OperationalHealth
{
    private sealed class State { public string Value = "Healthy", Candidate = "Healthy"; public DateTimeOffset CandidateSince;
        public string? Incident; public DateTimeOffset? Since; }
    private readonly Dictionary<string, State> _states = new() { ["Listeners"] = new(), ["Management"] = new(),
        ["Upstream"] = new(), ["Processing"] = new(), ["Capacity"] = new(), ["Persistence"] = new() };
    private readonly Queue<(DateTimeOffset At, DnsCounters Counts)> _window = new();
    private readonly Queue<OperationalEvent> _events = new();
    private readonly object _gate = new(); private readonly string _instance; private readonly HealthDefaults _defaults;
    private long _sequence, _incident;
    public OperationalHealth(string instance, HealthDefaults? defaults = null)
    { _instance = instance; _defaults = defaults ?? new();
        if (_defaults.WindowSeconds is < 1 or > 120 || _defaults.TriggerSeconds is < 1 or > 300 ||
            _defaults.CriticalSeconds < _defaults.TriggerSeconds || _defaults.CriticalSeconds > 300 || _defaults.RecoverySeconds is < 1 or > 300 ||
            _defaults.MinimumObservations is < 1 or > 10000 || _defaults.EventCapacity is < 1 or > 256 ||
            !double.IsFinite(_defaults.FailureRatio) || _defaults.FailureRatio is <= 0 or > 1 ||
            !double.IsFinite(_defaults.CriticalFailureRatio) || _defaults.CriticalFailureRatio < _defaults.FailureRatio || _defaults.CriticalFailureRatio > 1 ||
            !double.IsFinite(_defaults.RecoveryFailureRatio) || _defaults.RecoveryFailureRatio < 0 || _defaults.RecoveryFailureRatio >= _defaults.FailureRatio ||
            !double.IsFinite(_defaults.SlowP95Ms) || !double.IsFinite(_defaults.RecoveryP95Ms) || _defaults.RecoveryP95Ms < 0 || _defaults.SlowP95Ms <= _defaults.RecoveryP95Ms)
            throw new ArgumentException("Invalid health defaults"); }
    public void Evaluate(DnsServiceStatus status, DnsCounters counts, LatencySummary latency, DateTimeOffset now)
    {
        lock (_gate)
        {
            _window.Enqueue((now, counts));
            while (_window.Count > _defaults.WindowSeconds + 2 || (_window.Count > 1 && (now - _window.Peek().At).TotalSeconds > _defaults.WindowSeconds)) _window.Dequeue();
            var baseline = _window.Peek().Counts;
            var attempts = Math.Max(0, counts.UpstreamAttempts - baseline.UpstreamAttempts);
            var failures = Math.Max(0, counts.UpstreamFailures - baseline.UpstreamFailures);
            var completed = Math.Max(0, counts.Completed - baseline.Completed - (counts.Cancelled - baseline.Cancelled));
            var processingFailures = Math.Max(0, counts.Failed - baseline.Failed) + Math.Max(0, counts.CapacityDropped - baseline.CapacityDropped);
            var drops = counts.CapacityDropped - baseline.CapacityDropped + counts.TcpConnectionsRejected - baseline.TcpConnectionsRejected;
            var transport = counts.TransportFailures - baseline.TransportFailures;
            var evidence = attempts >= _defaults.MinimumObservations;
            var processingEvidence = completed >= _defaults.MinimumObservations;
            var upstreamRatio = failures / (double)Math.Max(1, attempts);
            var processingRatio = processingFailures / (double)Math.Max(1, completed);
            // Startup/stopping are not outages. Explicit faults are immediate, even outside Running.
            var running = status.RuntimeState is "Running" or "Degraded";
            Change("Listeners", status.UdpState == "Faulted" || status.TcpState == "Faulted" || (running && (!status.UdpListening || !status.TcpListening)) ? "Critical" : "Healthy", now, true);
            Change("Management", status.ManagementState == "Faulted" || (running && !status.ManagementListening) ? "Critical" : "Healthy", now, true);
            Change("Persistence", status.PersistenceFault != "" || (running && !status.PolicyLoaded) ? "Degraded" : "Healthy", now, true);
            var upstreamBad = evidence && (upstreamRatio >= _defaults.FailureRatio || (latency.Samples >= _defaults.MinimumObservations && latency.P95Ms > _defaults.SlowP95Ms));
            var upstreamGood = evidence && upstreamRatio <= _defaults.RecoveryFailureRatio && (latency.P95Ms == null || latency.P95Ms < _defaults.RecoveryP95Ms);
            Change("Upstream", upstreamBad ? "Degraded" : upstreamGood ? "Healthy" : "Hold", now);
            Change("Processing", processingEvidence && processingRatio >= _defaults.CriticalFailureRatio ? "Critical" :
                (processingEvidence && processingRatio >= _defaults.FailureRatio) || transport >= _defaults.MinimumObservations ? "Degraded" :
                processingEvidence && processingRatio <= _defaults.RecoveryFailureRatio && transport == 0 ? "Healthy" : "Hold", now);
            Change("Capacity", drops >= _defaults.MinimumObservations ? "Degraded" : "Healthy", now);
        }
    }
    private void Change(string component, string target, DateTimeOffset now, bool immediate = false)
    {
        var state = _states[component];
        if (target == "Hold") { state.Candidate = state.Value; state.CandidateSince = now; return; }
        if (target == state.Value) { state.Candidate = target; state.CandidateSince = now; return; }
        if (state.Candidate != target) { state.Candidate = target; state.CandidateSince = now; }
        var duration = target == "Healthy" ? _defaults.RecoverySeconds : target == "Critical" ? _defaults.CriticalSeconds : _defaults.TriggerSeconds;
        var elapsed = (now - state.CandidateSince).TotalSeconds;
        // Sustained severe processing symptoms first warn, then escalate within the same incident.
        if (!immediate && target == "Critical" && state.Value == "Healthy" && elapsed >= _defaults.TriggerSeconds && elapsed < duration)
            target = "Degraded";
        else if (!(immediate && target != "Healthy") && elapsed < duration) return;
        var recovery = target == "Healthy"; var previousIncident = state.Incident;
        state.Value = target; state.Since = now;
        state.Incident = recovery ? null : previousIncident ?? $"{_instance}:{++_incident}";
        var type = component.ToUpperInvariant() + (recovery ? "_RECOVERED" : target == "Critical" ? "_CRITICAL" : "_DEGRADED");
        _events.Enqueue(new(++_sequence, _instance, state.Incident ?? previousIncident!, component, type,
            recovery ? "Recovery" : target == "Critical" ? "Critical" : "Warning", now, target, "engine." + type.ToLowerInvariant(), recovery ? previousIncident : null));
        while (_events.Count > _defaults.EventCapacity) _events.Dequeue();
    }
    public HealthComponent[] Components() { lock (_gate) return _states.Select(x => new HealthComponent(x.Key, x.Value.Value, x.Value.Incident, x.Value.Since)).ToArray(); }
    public string Overall { get { lock (_gate) return _states.Values.Any(s => s.Value == "Critical") ? "Critical" : _states.Values.Any(s => s.Value == "Degraded") ? "Degraded" : "Healthy"; } }
    public OperationalEventBatch Read(long after = 0)
    { lock (_gate) return new(1, _instance, _sequence, after > _sequence || (_events.Count > 0 && after < _events.Peek().Sequence - 1),
        _events.Where(e => e.Sequence > after).ToArray(), Components()); }
}

public sealed class EngineDiagnostics
{
    private readonly EngineRuntimeStatus _status; private readonly DnsTelemetry _telemetry; private readonly string _instance;
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow; private readonly long _startTicks = Stopwatch.GetTimestamp();
    private readonly object _snapshotGate = new(); private readonly Process _process = Process.GetCurrentProcess();
    private TimeSpan _previousCpu; private long _previousTicks; private double? _cpu;
    public OperationalHealth Health { get; }
    public EngineDiagnostics(EngineRuntimeStatus status, DnsTelemetry telemetry, string instance, HealthDefaults? defaults = null)
    { _status = status; _telemetry = telemetry; _instance = instance; Health = new(instance, defaults); }
    public EngineDiagnosticsSnapshot Snapshot()
    {
        lock (_snapshotGate)
        {
            var ticks = Stopwatch.GetTimestamp();
            TimeSpan cpu; long? memory = null;
            try { _process.Refresh(); cpu = _process.TotalProcessorTime; memory = _process.WorkingSet64; }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            { cpu = _previousCpu; _cpu = null; _previousTicks = 0; }
            if (_previousTicks != 0 && ticks - _previousTicks >= Stopwatch.Frequency / 2)
                _cpu = Math.Max(0, (cpu - _previousCpu).TotalSeconds / ((ticks - _previousTicks) / (double)Stopwatch.Frequency) / Environment.ProcessorCount * 100);
            if (_previousTicks == 0 || ticks - _previousTicks >= Stopwatch.Frequency / 2) { _previousCpu = cpu; _previousTicks = ticks; }
            return new(1, _instance, DateTimeOffset.UtcNow, _telemetry.Counters(), _telemetry.Pressure(),
                _telemetry.UpstreamLatency.Snapshot(), _telemetry.ProcessingLatency.Snapshot(), _telemetry.Resolvers(),
                new((ticks - _startTicks) / (double)Stopwatch.Frequency, _cpu, memory, Environment.ProcessId, _started,
                    typeof(EngineDiagnostics).Assembly.GetName().Version?.ToString() ?? "Unknown"), Health.Overall, Health.Components());
        }
    }
    public void EvaluateOnce()
    { var snapshot = Snapshot(); Health.Evaluate(_status.GetSnapshot(), snapshot.Counters, snapshot.UpstreamLatency, snapshot.SnapshotUtc); }
    public async Task RunAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try { do { EvaluateOnce(); } while (await timer.WaitForNextTickAsync(token)); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }

    }
}
