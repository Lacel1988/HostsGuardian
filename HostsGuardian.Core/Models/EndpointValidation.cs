namespace HostsGuardian.Core.Models;

public sealed record EndpointValidationRequest(string RequestId,string Address,string Interface);
public sealed record ValidatorHealth(string State,string Reason,bool ActiveValidationEnabled,DateTimeOffset CheckedAtUtc);
public sealed record EndpointValidationResult(string RequestId,string Address,string Interface,
    DateTimeOffset RequestedAtUtc,DateTimeOffset ObservedAtUtc,DateTimeOffset? ConfirmedAtUtc,
    DateTimeOffset? ValidatedAtUtc,DateTimeOffset ExpiresAtUtc,string Method,string Outcome,string[] Macs,string Reason);
