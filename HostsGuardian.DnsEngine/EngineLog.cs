namespace HostsGuardian.DnsEngine;

/// <summary>Operational events only: never pass credentials, request bodies, or raw exception messages.</summary>
public static class EngineLog
{
    public static void Information(string component, string message)
        => Console.WriteLine($"[INFO] [{component}] {message}");

    public static void Warning(string component, string message)
        => Console.Error.WriteLine($"[WARN] [{component}] {message}");

    public static void Failure(string component, string message)
        => Console.Error.WriteLine($"[ERROR] [{component}] {message}");
}
