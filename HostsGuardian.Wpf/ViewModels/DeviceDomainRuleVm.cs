using L = HostsGuardian.Wpf.Localization.LocalizationService;
using HostsGuardian.Core.Models;
using HostsGuardian.Wpf.Infrastructure;
namespace HostsGuardian.Wpf.ViewModels;

public sealed class DeviceDomainRuleVm : ObservableObject
{
    public string Domain { get; }
    private DeviceDomainRuleState _state;
    private readonly Func<DeviceDomainRuleState, bool> _changed;
    private readonly Func<DeviceDomainRuleState, string> _effective;
    public DeviceDomainRuleVm(string domain, DeviceDomainRuleState state, Func<DeviceDomainRuleState, bool> changed,
        Func<DeviceDomainRuleState, string> effective)
    { Domain = domain; _state = state; _changed = changed; _effective = effective; }
    public DeviceDomainRuleState State
    {
        get => _state;
        set
        {
            if (_state == value) return;
            if (!_changed(value)) { OnPropertyChanged(nameof(State)); return; }
            Set(ref _state, value);
            OnPropertyChanged(nameof(Indicator)); OnPropertyChanged(nameof(Effective));
        }
    }
    public string Indicator => State switch
    { DeviceDomainRuleState.Allow => L.T("✓ ALLOW"), DeviceDomainRuleState.Block => L.T("⛔ BLOCK"), _ => L.T("○ INHERIT") };
    public void Relocalize() { OnPropertyChanged(nameof(Indicator)); OnPropertyChanged(nameof(Effective)); }
    public string Effective => _effective(State);
}
