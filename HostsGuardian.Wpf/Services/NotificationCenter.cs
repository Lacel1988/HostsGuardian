using System.Collections.ObjectModel;
using HostsGuardian.Wpf.Infrastructure;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

namespace HostsGuardian.Wpf.Services;

public enum NotificationSeverity { Critical, Warning, Information }
public sealed class NotificationItem : ObservableObject
{
    public string Key { get; }
    public NotificationCategory Category { get; }
    public NotificationSeverity Severity { get; }
    public string Page { get; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.Now;
    private readonly string _title, _message;
    public string Title => L.T(_title);
    public string Message => L.T(_message);
    public string SeverityText => L.T(Severity.ToString());
    public string StateText => L.T(Resolved ? "Resolved" : IsRead ? "Read" : "Unread");
    private bool _isRead, _resolved;
    public bool IsRead { get => _isRead; set { if (Set(ref _isRead, value)) OnPropertyChanged(nameof(StateText)); } }
    public bool Resolved { get => _resolved; set { if (Set(ref _resolved, value)) OnPropertyChanged(nameof(StateText)); } }
    public NotificationItem(string key, NotificationCategory category, NotificationSeverity severity, string title, string message, string page)
    { Key = key; Category = category; Severity = severity; _title = title; _message = message; Page = page; }
    public void Relocalize() { OnPropertyChanged(nameof(Title)); OnPropertyChanged(nameof(Message)); OnPropertyChanged(nameof(SeverityText)); OnPropertyChanged(nameof(StateText)); }
}

/// <summary>Unpackaged desktop transport seam. No silent registry, shortcut or installer registration.</summary>
public interface IDesktopNotificationSink { bool Available { get; } void Show(NotificationItem notification); }
public sealed class UnregisteredDesktopNotificationSink : IDesktopNotificationSink
{
    public bool Available => false;
    public void Show(NotificationItem notification) { }
}

/// <summary>Receives real observations only. Page refresh and navigation are not observations.</summary>
public sealed class NotificationCenter : ObservableObject
{
    public ObservableCollection<NotificationItem> Items { get; } = new();
    private readonly UiPreferences _preferences;
    private readonly IDesktopNotificationSink _desktop;
    private readonly Func<bool> _foreground;
    public int UnreadCount => Items.Count(i => !i.IsRead);
    public string CriticalMessage => string.Join(" · ", Items.Where(i => !i.Resolved && i.Severity == NotificationSeverity.Critical).Select(i => i.Title));
    public bool HasCritical => Items.Any(i => !i.Resolved && i.Severity == NotificationSeverity.Critical);
    public NotificationCenter(UiPreferences? preferences = null, IDesktopNotificationSink? desktop = null, Func<bool>? foreground = null)
    { _preferences = preferences ?? UiPreferences.Current; _desktop = desktop ?? new UnregisteredDesktopNotificationSink(); _foreground = foreground ?? (() => true); }
    public void Observe(string key, bool problem, NotificationCategory category, NotificationSeverity severity, string title, string message, string page)
    {
        var existing = Items.LastOrDefault(i => i.Key == key && !i.Resolved);
        if (!problem)
        {
            if (existing == null) return;
            existing.Resolved = true;
            if (_preferences.Enabled(NotificationCategory.Recovery)) Add(new(key + ".recovery", NotificationCategory.Recovery,
                NotificationSeverity.Information, "Problem resolved", "A new result confirms that a previously reported problem has been resolved.", page));
            Changed(); return;
        }
        if (existing != null) return;
        // Critical conditions stay visible even when delivery for this category is disabled.
        if (!_preferences.Enabled(category) && severity != NotificationSeverity.Critical) return;
        Add(new(key, category, severity, title, message, page));
    }
    private void Add(NotificationItem item)
    {
        Items.Add(item);
        // Keep active conditions; bound resolved history and information.
        while (Items.Count > 100 && Items.FirstOrDefault(i => i.Resolved || i.Severity == NotificationSeverity.Information) is { } removable) Items.Remove(removable);
        if (_preferences.Enabled(item.Category) && item.Severity != NotificationSeverity.Information && !_foreground() && _desktop.Available) _desktop.Show(item);
        Changed();
    }
    public void MarkRead(NotificationItem item) { item.IsRead = true; Changed(); }
    public void MarkAllRead() { foreach (var item in Items) item.IsRead = true; Changed(); }
    public void Relocalize() { foreach (var item in Items) item.Relocalize(); Changed(); }
    private void Changed() { OnPropertyChanged(nameof(UnreadCount)); OnPropertyChanged(nameof(CriticalMessage)); OnPropertyChanged(nameof(HasCritical)); }
}
