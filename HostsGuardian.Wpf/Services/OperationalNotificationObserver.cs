using HostsGuardian.Core.Models;

namespace HostsGuardian.Wpf.Services;

/// <summary>Current component incidents become actionable conditions, not a raw event feed.</summary>
public static class OperationalNotificationObserver
{
    public static void Observe(NotificationCenter center, OperationalEventBatch batch)
    {
        foreach (var component in batch.Components)
        {
            var problem = component.State != "Healthy";
            center.Observe("component." + component.Component, problem, NotificationCategory.EngineDns,
                component.State == "Critical" ? NotificationSeverity.Critical : NotificationSeverity.Warning,
                component.Component switch
                {
                    "Upstream" => "Upstream degraded",
                    "Persistence" => "Policy persistence requires attention",
                    "Capacity" => "Engine capacity requires attention",
                    "Listeners" => "DNS listeners require attention",
                    "Management" => "Management requires attention",
                    _ => "DNS processing requires attention"
                }, "Read Engine health and local Monitor diagnostics before changing policy.", "Router");
        }
    }
}
