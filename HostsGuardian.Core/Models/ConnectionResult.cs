namespace HostsGuardian.Core.Models;
public enum ConnectionState { CredentialUnavailable, Unreachable, Timeout, NetworkFailure, TrustFailure, AuthenticationFailed, Authenticated, Incompatible, EngineError, InvalidSettings }
public sealed record ConnectionResult(ConnectionState State, string Message, DnsServiceStatus? Transport = null)
{
    public bool Ok => State == ConnectionState.Authenticated;
}
