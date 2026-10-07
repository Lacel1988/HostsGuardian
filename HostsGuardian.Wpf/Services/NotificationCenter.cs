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
    public DateTimeOffset? ExpiresAtUtc { get; init; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.Now;
    private readonly string _title, _message;
    public string Title => L.T(_title);
    public object[]? MessageArguments { get; init; }
    public string Message => MessageArguments == null ? L.T(_message) : L.F(_message, MessageArguments);
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
public interface IDesktopNotificationSink { bool Available { get; } void Show(NotificationItem notification); void Remove(string key) { } }
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
    private readonly NotificationDeliveryJournal? _journal;
    private readonly HashSet<NotificationItem> _desktopAttempted = new();
    private readonly Dictionary<(string Key, NotificationSeverity Severity), DateTimeOffset> _desktopDelivered = new();
    public int UnreadCount => Items.Count(i => !i.IsRead);
    public string CriticalMessage => string.Join(" · ", Items.Where(i => !i.Resolved && i.Severity == NotificationSeverity.Critical).Select(i => i.Title));
    public bool HasCritical => Items.Any(i => !i.Resolved && i.Severity == NotificationSeverity.Critical);
    public NotificationCenter(UiPreferences? preferences = null, IDesktopNotificationSink? desktop = null, Func<bool>? foreground = null, NotificationDeliveryJournal? journal = null)
    { _journal = journal; _preferences = preferences ?? UiPreferences.Current; _desktop = desktop ?? new UnregisteredDesktopNotificationSink(); _foreground = foreground ?? (() => true); }
    public void Observe(string key, bool problem, NotificationCategory category, NotificationSeverity severity, string title, string message, string page)
    {
        var existing = Items.LastOrDefault(i => i.Key == key && !i.Resolved);
        if (!problem)
        {
            if (existing == null) return;
            existing.Resolved = true; _desktop.Remove(existing.Key);
            if (_preferences.Enabled(NotificationCategory.Recovery)) Add(new(key + ".recovery", NotificationCategory.Recovery,
                NotificationSeverity.Information, "Problem resolved", "A new result confirms that a previously reported problem has been resolved.", page));
            Changed(); return;
        }
        if (existing != null)
        {
            if (severity != NotificationSeverity.Critical || existing.Severity == NotificationSeverity.Critical) return;
            existing.Resolved = true; // escalation is not a confirmed recovery
        }
        var recent = Items.LastOrDefault(i => i.Key == key && i.Severity == severity);
        if (recent != null && DateTimeOffset.Now - recent.Timestamp < TimeSpan.FromMinutes(2))
        { recent.Resolved = false; recent.IsRead = false; DeliverDesktop(recent); Changed(); return; }
        // Critical conditions stay visible even when delivery for this category is disabled.
        if (!_preferences.Enabled(category) && severity != NotificationSeverity.Critical) return;
        Add(new(key, category, severity, title, message, page));
    }
    private void Add(NotificationItem item)
    {
        if (item.Severity == NotificationSeverity.Information && Items.Any(i => i.Key == item.Key && DateTimeOffset.Now - i.Timestamp < TimeSpan.FromMinutes(2)))
        { Changed(); return; }
        Items.Add(item);
        // Keep active conditions; bound resolved history and information.
        while (Items.Count > 100 && Items.FirstOrDefault(i => i.Resolved || i.Severity == NotificationSeverity.Information) is { } removable) Items.Remove(removable);
        DeliverDesktop(item);
        Changed();
    }
    private void DeliverDesktop(NotificationItem item)
    {
        if (!_preferences.Enabled(item.Category) || _foreground() || !_desktop.Available || _desktopAttempted.Contains(item) ||
            item.ExpiresAtUtc is { } expiry && expiry <= DateTimeOffset.UtcNow) return;
        var key = (item.Key, item.Severity); var now = DateTimeOffset.Now;
        if (_desktopDelivered.TryGetValue(key, out var last) && now - last < TimeSpan.FromMinutes(2)) return;
        if (_journal != null && !_journal.Reserve(item.Key + "." + item.Severity,
            item.ExpiresAtUtc ?? now.AddMinutes(2), now)) return;
        _desktop.Show(item); _desktopDelivered[key] = now; _desktopAttempted.Add(item);
        foreach (var expired in _desktopDelivered.Where(p => now - p.Value > TimeSpan.FromMinutes(2)).Select(p => p.Key).ToArray()) _desktopDelivered.Remove(expired);
    }
    public void FlushDesktop()
    {
        _desktopAttempted.RemoveWhere(i => !Items.Contains(i));
        foreach (var item in Items.Where(i => !i.Resolved && !i.IsRead &&
            (i.ExpiresAtUtc != null || DateTimeOffset.Now - i.Timestamp < TimeSpan.FromMinutes(2)))) DeliverDesktop(item);
    }
    public void Publish(NotificationItem item) { if (_preferences.Enabled(item.Category)) Add(item); }
    public void Withdraw(string key)
    {
        foreach (var item in Items.Where(i => i.Key == key)) item.Resolved = true;
        _desktop.Remove(key); Changed();
    }
    public void MarkRead(NotificationItem item) { item.IsRead = true; Changed(); }
    public void MarkAllRead() { foreach (var item in Items) item.IsRead = true; Changed(); }
    public void Relocalize() { foreach (var item in Items) item.Relocalize(); Changed(); }
    private void Changed() { OnPropertyChanged(nameof(UnreadCount)); OnPropertyChanged(nameof(CriticalMessage)); OnPropertyChanged(nameof(HasCritical)); }
}
