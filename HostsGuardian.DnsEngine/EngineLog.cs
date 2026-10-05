namespace HostsGuardian.DnsEngine;

/// <summary>Operational events only: never pass credentials, request bodies, or raw exception messages.</summary>
public static class EngineLog
{
    private static readonly object Gate = new();
    private static readonly Queue<MonitorEvent> Events = new();
    public static MonitorEvent[] RecentEvents() { lock (Gate) return Events.ToArray(); }
    private static string Record(string level, string component, string message)
    {
        var clean = HostsGuardian.Core.Services.SecretRedactor.Clean(message);
        clean = clean.Length > 240 ? clean[..240] : clean;
        component = component.Length > 40 ? component[..40] : component;
        lock (Gate)
        {
            if (Events.Count == 64) Events.Dequeue();
            Events.Enqueue(new(DateTimeOffset.UtcNow, level, component, clean));
        }
        return $"[{level}] [{component}] {clean}";
    }
    public static void Information(string component, string message)
        => Console.WriteLine(Record("INFO", component, message));

    public static void Warning(string component, string message)
        => Console.Error.WriteLine(Record("WARN", component, message));

    public static void Failure(string component, string message)
        => Console.Error.WriteLine(Record("ERROR", component, message));
}
