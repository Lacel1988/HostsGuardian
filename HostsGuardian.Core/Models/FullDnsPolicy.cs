using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace HostsGuardian.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<DeviceDomainRuleState>))]
public enum DeviceDomainRuleState { Inherit, Allow, Block }
public sealed record DeviceRegistration(Guid DeviceId, string Name, string? Mac, string Scope, string Provenance)
{
    // Future explicit WPF linking: never accepted automatically from IP/name/fingerprint.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcceptedNetworkIdentity[]? AcceptedNetworkIdentities {get;init;}
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DeviceMetadata? Metadata { get; init; }
}
public sealed record AcceptedNetworkIdentity(string Mac,string Scope,string Provenance,DateTimeOffset AcceptedAtUtc);
public sealed record DeviceDomainOverride(Guid DeviceId, string Domain, DeviceDomainRuleState State);
public sealed record FullDnsPolicy(int SchemaVersion, ImmutableArray<string> GlobalBlockedDomains,
    ImmutableArray<DeviceRegistration> Devices, ImmutableArray<DeviceDomainOverride> Overrides)
{
    public static FullDnsPolicy Empty { get; } = new(2, [], [], []);
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PolicyProgram? Program { get; init; }
}
public sealed record FullPolicyRead(long? Revision, FullDnsPolicy Policy, string InstanceId = "");
public sealed record FullPolicyReplace(long? ExpectedRevision, FullDnsPolicy Policy, string? ExpectedInstanceId = null);
public sealed record AddressBindingObservation(string Address, string? NetworkScope, Guid DeviceId,
    string Provenance, DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc, bool Validated)
{
    public DateTimeOffset? ValidatedAtUtc {get;init;}
    public string? ValidationMethod {get;init;}
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? MacEvidence {get;init;}
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Interface {get;init;}
}
public sealed record BindingRead(long Generation, ImmutableArray<AddressBindingObservation> Observations);
public sealed record BindingReplace(long ExpectedGeneration, ImmutableArray<AddressBindingObservation> Observations);
public sealed record EffectivePolicyExplanation(long? Revision, long MappingGeneration, Guid? DeviceId,
    string IdentityState, string Domain, DeviceDomainRuleState ExplicitState, bool Blocked, string Reason)
{
    public ImmutableArray<DecisionEvidence> DecisionChain { get; init; } = [];
    public DecisionEvidence? Winner { get; init; }
}
