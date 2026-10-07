namespace HostsGuardian.Core.Models;

public sealed record TopologyEvidence(string Provider,string Confidence,string Explanation,
    DateTimeOffset? ObservedAtUtc,DateTimeOffset? ReadAtUtc,DateTimeOffset? ConfirmedAtUtc);
public sealed record TopologyNode(string Id,string Kind,string Name,Guid? DeviceId,string DeviceType,
    string Presence,string Access,string[] Addresses,string[] Macs,string DnsActivity,string Coverage,
    string Binding,string PolicyIdentity,TopologyEvidence[] Evidence)
{ public string? NetworkId {get;init;} }
public sealed record TopologyLink(string Id,string From,string To,string Relationship,string Confidence,
    string Explanation,DateTimeOffset? ObservedAtUtc);
public sealed record TopologyNetwork(string Id,string Name,string MembershipConfidence);
public sealed record AccessTopologyEvidence(Guid ObservationId,string Technology,string ParentId,string NetworkId,
    string NetworkName,string Confidence,string Provider,string Explanation,DateTimeOffset ObservedAtUtc,DateTimeOffset ExpiresAtUtc);
public sealed record TopologySnapshot(int SchemaVersion,DateTimeOffset SnapshotUtc,TopologyNode[] Nodes,
    TopologyLink[] Links,TopologyNetwork[] Networks,int OmittedNodes,int OmittedLinks);
