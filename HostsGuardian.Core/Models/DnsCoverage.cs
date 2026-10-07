namespace HostsGuardian.Core.Models;

/// <summary>Coverage is evidence about resolver steering, never implied by process health.
/// Complete means conventional DNS paths within the explicitly assessed scope, not a guarantee against encrypted DNS.</summary>
public sealed record DnsCoverage
{
    public bool? HostIpv6Active { get; init; }
    public string[] HostCachedIpv6Resolvers { get; init; } = [];
    public string HostEvidence { get; init; } = "Unknown; host evidence does not establish client resolver selection";
    public string State { get; init; } = "UNKNOWN";
    public string Ipv4Advertisement { get; init; } = "Unknown";
    public string Ipv6Advertisement { get; init; } = "Unknown";
    public string AlternativeResolver { get; init; } = "Unknown";
    public string Scope { get; init; } = "Network advertisement not assessed";
    public static DnsCoverage Evaluate(bool ipv4Ready, bool ipv6Ready, bool? ipv6Active,
        string ipv4Advertisement = "Unknown", string ipv6Advertisement = "Unknown", string alternativeResolver = "Unknown")
    {
        static bool Valid(string value) => value is "HostsGuardian" or "Alternative" or "Unknown";
        if (!Valid(ipv4Advertisement) || !Valid(ipv6Advertisement) || !Valid(alternativeResolver))
            return new();
        var partial = !ipv4Ready || alternativeResolver == "Alternative" || ipv4Advertisement == "Alternative" ||
            ipv6Active == true && (!ipv6Ready || ipv6Advertisement == "Alternative");
        // Configuration and reachable listeners establish intent/capability, never exclusive client coverage.
        return new() { State = partial ? "PARTIAL" : "UNKNOWN",
            Ipv4Advertisement = ipv4Advertisement, Ipv6Advertisement = ipv6Advertisement,
            AlternativeResolver = alternativeResolver,
            Scope = "Configuration/readiness evidence only; client resolver selection and coverage unconfirmed" };
    }
}
