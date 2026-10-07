using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;

namespace HostsGuardian.Wpf.Services;

/// <summary>Validated local authoring boundary. Rejected edits/restores keep the previous draft.</summary>
public sealed class PolicyDraftSession
{
    public FullDnsPolicy Policy { get; private set; }
    public PolicyDraftSession(FullDnsPolicy policy) => Policy = PolicyCanonicalization.Canonicalize(policy);
    public void Replace(FullDnsPolicy candidate)
    {
        var valid = PolicyCanonicalization.Canonicalize(candidate);
        Policy = valid;
    }
    public void Restore(string json) => Replace(PolicyBackup.Import(json));
    public void Save(Action<FullDnsPolicy> save) => save(Policy);
}
