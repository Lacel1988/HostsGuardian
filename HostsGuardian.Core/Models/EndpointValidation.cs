namespace HostsGuardian.Core.Models;

public sealed record EndpointValidationRequest(string RequestId,string Address,string Interface);
public sealed record ValidatorHealth(string State,string Reason,bool ActiveValidationEnabled,DateTimeOffset CheckedAtUtc)
{
    public string Mode {get;init;}="Passive";
    public int ApprovedTargetCount {get;init;}
    public DateTimeOffset? DeadlineUtc {get;init;}
    public double RemainingSeconds {get;init;}
    public string ModeReason {get;init;}="Disabled";
    public string PassiveDnsL2State {get;init;}="Disabled";
    public string PassiveDnsL2Reason {get;init;}="Receive-only evidence not enabled";
    public string Ipv6IdentityState {get;init;}="UnsupportedPassiveEvidence";
    public string? CaptureInstance {get;init;}
    public long InterfaceGeneration {get;init;}
}
public sealed record EndpointValidationResult(string RequestId,string Address,string Interface,
    DateTimeOffset RequestedAtUtc,DateTimeOffset ObservedAtUtc,DateTimeOffset? ConfirmedAtUtc,
    DateTimeOffset? ValidatedAtUtc,DateTimeOffset ExpiresAtUtc,string Method,string Outcome,string[] Macs,string Reason);
