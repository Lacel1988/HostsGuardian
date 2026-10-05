using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;
public static class FullPolicyValidation
{
    public static FullDnsPolicy Canonicalize(FullDnsPolicy candidate)
        => HostsGuardian.Core.Services.PolicyCanonicalization.Canonicalize(candidate);
}
