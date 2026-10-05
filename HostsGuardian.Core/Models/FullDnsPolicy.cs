using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace HostsGuardian.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<DeviceDomainRuleState>))]
public enum DeviceDomainRuleState { Inherit, Allow, Block }
public sealed record DeviceRegistration(Guid DeviceId, string Name, string? Mac, string Scope, string Provenance);
public sealed record DeviceDomainOverride(Guid DeviceId, string Domain, DeviceDomainRuleState State);
public sealed record FullDnsPolicy(int SchemaVersion, ImmutableArray<string> GlobalBlockedDomains,
    ImmutableArray<DeviceRegistration> Devices, ImmutableArray<DeviceDomainOverride> Overrides)
{
    public static FullDnsPolicy Empty { get; } = new(2, [], [], []);
}
public sealed record FullPolicyRead(long? Revision, FullDnsPolicy Policy, string InstanceId = "");
public sealed record FullPolicyReplace(long? ExpectedRevision, FullDnsPolicy Policy, string? ExpectedInstanceId = null);
public sealed record AddressBindingObservation(string Address, string? NetworkScope, Guid DeviceId,
    string Provenance, DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc, bool Validated);
public sealed record BindingRead(long Generation, ImmutableArray<AddressBindingObservation> Observations);
public sealed record BindingReplace(long ExpectedGeneration, ImmutableArray<AddressBindingObservation> Observations);
public sealed record EffectivePolicyExplanation(long? Revision, long MappingGeneration, Guid? DeviceId,
    string IdentityState, string Domain, DeviceDomainRuleState ExplicitState, bool Blocked, string Reason);
