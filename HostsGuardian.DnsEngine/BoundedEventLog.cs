namespace HostsGuardian.DnsEngine;

/// <summary>One warning per fixed event category per 30 seconds, per component instance.</summary>
internal sealed class BoundedEventLog
{
    private readonly object _gate = new();
    private readonly Dictionary<string, long> _lastEvents = new();

    public void Warning(string component, string category)
    {
        lock (_gate)
        {
            var now = Environment.TickCount64;
            if (_lastEvents.TryGetValue(category, out var previous) && now - previous < 30000)
                return;
            _lastEvents[category] = now;
        }
        EngineLog.Warning(component, category);
    }
}
