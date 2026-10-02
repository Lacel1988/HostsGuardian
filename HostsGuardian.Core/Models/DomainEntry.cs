using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HostsGuardian.Core.Models;

public sealed class DomainEntry : INotifyPropertyChanged
{
    private string? _domain;
    private bool _hostsBlocked;
    private bool _dnsBlocked;
    private string? _notes;

    public string? Domain { get => _domain; set => Set(ref _domain, value); }
    // Missing flags never implicitly authorize filtering of legacy entries.
    public bool HostsBlocked { get => _hostsBlocked; set => Set(ref _hostsBlocked, value); }
    public bool DnsBlocked { get => _dnsBlocked; set => Set(ref _dnsBlocked, value); }
    public string? Notes { get => _notes; set => Set(ref _notes, value); }
    public event PropertyChangedEventHandler? PropertyChanged;

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
