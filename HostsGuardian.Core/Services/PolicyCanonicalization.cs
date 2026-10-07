using System.Collections.Immutable;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.Core.Services;

public static class PolicyCanonicalization
{
    public static FullDnsPolicy Canonicalize(FullDnsPolicy candidate)
    {
        if (candidate == null || candidate.SchemaVersion is not (2 or 3) || candidate.GlobalBlockedDomains.IsDefault
            || candidate.Devices.IsDefault || candidate.Overrides.IsDefault || candidate.Devices.Length > 4096
            || candidate.Overrides.Length > 16384) throw new ArgumentException("Invalid policy schema");
        var domains = candidate.GlobalBlockedDomains.Select(Normalize).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray();
        var devices = candidate.Devices.Select(d =>
        {
            if (d == null || d.DeviceId == Guid.Empty || string.IsNullOrWhiteSpace(d.Name) || d.Name.Length > 128
                || string.IsNullOrWhiteSpace(d.Scope) || d.Scope.Length > 128 || string.IsNullOrWhiteSpace(d.Provenance)
                || d.Provenance.Length > 128) throw new ArgumentException("Invalid device registry");
            var mac = d.Mac == null ? null : DevicePolicyIdentity.NormalizeMac(d.Mac);
            if (mac == "") throw new ArgumentException("Invalid MAC evidence");
            if (candidate.SchemaVersion == 2 && d.Metadata != null) throw new ArgumentException("Metadata requires schema 3");
            if(d.AcceptedNetworkIdentities is {} identities && (candidate.SchemaVersion!=3 || identities.Length>8 || identities.Any(i=>i is null || DevicePolicyIdentity.NormalizeMac(i.Mac)=="" || string.IsNullOrWhiteSpace(i.Scope) || i.Scope.Length>128 || string.IsNullOrWhiteSpace(i.Provenance) || i.Provenance.Length>128 || i.AcceptedAtUtc==default) || identities.Select(i=>(DevicePolicyIdentity.NormalizeMac(i.Mac),i.Scope)).Distinct().Count()!=identities.Length))throw new ArgumentException("Invalid explicit network identities");
            return d with { Mac = mac, Metadata = PolicyProgramValidation.Metadata(d.Metadata),AcceptedNetworkIdentities=d.AcceptedNetworkIdentities?.Select(i=>i with{Mac=DevicePolicyIdentity.NormalizeMac(i.Mac)}).ToArray() };
        }).OrderBy(d => d.DeviceId).ToImmutableArray();
        if (devices.Select(d => d.DeviceId).Distinct().Count() != devices.Length) throw new ArgumentException("Duplicate DeviceId");
        var overrides = candidate.Overrides.Select(o =>
        {
            if (o == null || !Enum.IsDefined(o.State) || !devices.Any(d => d.DeviceId == o.DeviceId))
                throw new ArgumentException("Invalid policy reference");
            return o with { Domain = Normalize(o.Domain) };
        }).OrderBy(o => o.DeviceId).ThenBy(o => o.Domain, StringComparer.Ordinal).ToImmutableArray();
        if (overrides.Select(o => (o.DeviceId, o.Domain)).Distinct().Count() != overrides.Length)
            throw new ArgumentException("Duplicate device override");
        if (candidate.SchemaVersion == 2 && candidate.Program != null) throw new ArgumentException("Program requires schema 3");
        var program = candidate.SchemaVersion == 3 ? PolicyProgramValidation.Canonicalize(candidate.Program ?? PolicyProgram.Empty, devices) : null;
        var canonical = new FullDnsPolicy(candidate.SchemaVersion, domains, devices, overrides) { Program = program };
        if (candidate.SchemaVersion == 3 && System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(canonical,
            new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase }).Length > 49152)
            throw new ArgumentException("Program exceeds Management API policy budget");
        PolicyEvidenceBudget.Validate(canonical);
        return canonical;
    }
    private static string Normalize(string value)
    {
        var normalized = DomainName.Normalize(value);
        if (normalized.Length == 0) throw new ArgumentException("Invalid domain");
        return normalized;
    }
}
