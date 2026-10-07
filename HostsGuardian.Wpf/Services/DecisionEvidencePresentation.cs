using HostsGuardian.Core.Models;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

namespace HostsGuardian.Wpf.Services;

/// <summary>Shared presentation of retained policy evidence, without changing its order or meaning.</summary>
public static class DecisionEvidencePresentation
{
    public static string Format(IEnumerable<DecisionEvidence> chain) => string.Join(Environment.NewLine,
        chain.Select((rule, index) =>
            $"{L.T(index == 0 ? "Winning rule" : "Overridden rule")}: {Layer(rule.Layer)} / {L.T(rule.State.ToString())} / {rule.Domain}; " +
            $"RuleId: {rule.RuleId}; GroupId: {rule.GroupId}; ProfileId: {rule.ProfileId}; ScheduleId: {rule.ScheduleId}; ServiceId: {rule.ServiceId}"));

    public static string Layer(PolicyLayer layer) => L.T(layer switch
    {
        PolicyLayer.DeviceOverride => "Device override",
        PolicyLayer.ActiveProfile => "Active Profile/Schedule",
        PolicyLayer.DeviceGroup => "Device Group",
        PolicyLayer.Global => "Global rule",
        _ => layer.ToString()
    });
}
