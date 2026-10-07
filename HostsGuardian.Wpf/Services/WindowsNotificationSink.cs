using Microsoft.Toolkit.Uwp.Notifications;
using System.Security.Cryptography;
using System.Text;
using Windows.UI.Notifications;

namespace HostsGuardian.Wpf.Services;

/// <summary>Per-user unpackaged Windows toast transport. Activation only navigates; never changes policy.</summary>
public sealed class WindowsNotificationSink : IDesktopNotificationSink
{
    public static WindowsNotificationSink Instance { get; } = new();
    public event Action<string>? Activated;
    public string? PendingPage { get; private set; }
    public void ConsumePending() { if (PendingPage is { } page) { PendingPage = null; Activated?.Invoke(page); } }
    private bool _ready;
    public bool Available => _ready;
    public string? LastFailure { get; private set; }
    public void Initialize()
    {
        if (_ready || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return;
        try
        {
        ToastNotificationManagerCompat.OnActivated += args =>
        {
            try
            {
            if (args.Argument == null || args.Argument.Length > 2048) return;
            var parsed = ToastArguments.Parse(args.Argument);
            var page = parsed.Contains("page") ? parsed["page"] : "Router";
            if (page is not ("Router" or "Devices" or "Domains" or "Policy")) page = "Router";
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(() => { PendingPage = page; ConsumePendingIfReady(); });
            }
            catch { LastFailure = "Windows notification activation unavailable"; }
        };
        _ready = true;
        }
        catch { LastFailure = "Windows notification registration unavailable"; }
    }
    private void ConsumePendingIfReady() { if (Activated != null) ConsumePending(); }
    private static string Tag(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..16];
    public void Show(NotificationItem notification)
    {
        if (!Available) return;
        try
        {
            var content = new ToastContentBuilder().AddArgument("page", notification.Page)
                .AddText("HostsGuardian — " + notification.Title).AddText(notification.Message).GetToastContent();
            var toast = new ToastNotification(content.GetXml())
            { Tag = Tag(notification.Key), Group = "HostsGuardian", ExpirationTime = notification.ExpiresAtUtc ?? DateTimeOffset.UtcNow.AddMinutes(10) };
            toast.Failed += (_, _) => LastFailure = "Windows rejected the notification";
            ToastNotificationManagerCompat.CreateToastNotifier().Show(toast);
            LastFailure = null;
        }
        catch { LastFailure = "Windows notification delivery unavailable"; }
    }
    public void Remove(string key)
    {
        try { if (Available) ToastNotificationManagerCompat.History.Remove(Tag(key), "HostsGuardian"); }
        catch { LastFailure = "Windows notification removal unavailable"; }
    }
}
