namespace HostsGuardian.Core.Models;

/// <summary>Read-only projection of user-authored registration metadata; never an execution binding.</summary>
public sealed record DeviceIdentityPresentation(Guid? DeviceId, string FriendlyName, string ObservedHostname,
    string State, string Confidence, string Provenance)
{
    public string[] Groups { get; init; } = [];
    public string DeviceType { get; init; } = "";
    public bool PrivateMacPossible { get; init; }
}
