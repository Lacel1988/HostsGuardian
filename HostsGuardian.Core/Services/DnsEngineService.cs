using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
public sealed class DnsEngineService
{
    private readonly Func<HttpClient>? _factory;
    private readonly ICredentialStore _credentials;
    public DnsEngineService(Func<HttpClient>? httpFactory = null, ICredentialStore? credentials = null)
    { _factory = httpFactory; _credentials = credentials ?? new ProtectedCredentialStore(); }
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };
    private async Task<(ConnectionResult result, string body)> Send(DnsEngineConfig cfg, string path, string? payload, CancellationToken ct)
    {
        Uri endpoint;
        try { endpoint = ManagementSecurity.Endpoint(cfg); }
        catch { return (new(ConnectionState.InvalidSettings, "Invalid Engine address or port"), ""); }
        string? token;
        try { token = string.IsNullOrEmpty(cfg.ApiToken) ? _credentials.Read(cfg.CredentialId) : cfg.ApiToken; }
        catch { return (new(ConnectionState.CredentialUnavailable, "Protected credential unavailable"), ""); }
        if (ManagementSecurity.ParseToken(token) == null) return (new(ConnectionState.CredentialUnavailable, "Credential unavailable"), "");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        ct = deadline.Token;
        var trustFailed = false;
        try
        {
            using var http = _factory?.Invoke() ?? new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
                { var valid = ManagementSecurity.ValidateCertificate(cert, cfg.TrustedCertificate, errors); trustFailed = !valid; return valid; }
            });
            http.Timeout = TimeSpan.FromSeconds(8);
            using var request = new HttpRequestMessage(payload == null ? HttpMethod.Get : HttpMethod.Post, new Uri(endpoint, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (payload != null) request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized) return (new(ConnectionState.AuthenticationFailed, "Authentication failed"), "");
            if ((int)response.StatusCode is >= 300 and < 400) return (new(ConnectionState.Incompatible, "Redirect refused"), "");
            if (!response.IsSuccessStatusCode) return (new(ConnectionState.EngineError, $"Engine returned HTTP {(int)response.StatusCode}"), "");
            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var memory = new MemoryStream();
            var buffer = new byte[4096]; int count;
            while ((count = await stream.ReadAsync(buffer, ct)) > 0)
            { if (memory.Length + count > 262144) return (new(ConnectionState.Incompatible, "Response exceeds size limit"), ""); await memory.WriteAsync(buffer.AsMemory(0, count), ct); }
            return (new(ConnectionState.Authenticated, "Engine online; authenticated"), Encoding.UTF8.GetString(memory.ToArray()));
        }
        catch (OperationCanceledException) { return (new(ConnectionState.Timeout, "Connection timed out or cancelled"), ""); }
        catch (HttpRequestException ex)
        {
            if (trustFailed || ex.HttpRequestError == HttpRequestError.SecureConnectionError) return (new(ConnectionState.TrustFailure, "Server certificate validation failed"), "");
            if (ex.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError) return (new(ConnectionState.Unreachable, "Engine unreachable"), "");
            return (new(ConnectionState.NetworkFailure, "Network failure"), "");
        }
        catch { return (new(ConnectionState.NetworkFailure, "Connection failed"), ""); }
    }
    public async Task<ConnectionResult> TestConnectionAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var (result, body) = await Send(cfg, "health", null, ct);
        if (!result.Ok) return result;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.GetProperty("engine").GetString() != "HostsGuardian.DnsEngine" || doc.RootElement.GetProperty("apiVersion").GetInt32() != 1)
                return new(ConnectionState.Incompatible, "Incompatible Engine response");
            var (statusResult, statusBody) = await Send(cfg, "dns/status", null, ct);
            if (!statusResult.Ok) return statusResult;
            var status = JsonSerializer.Deserialize<DnsServiceStatus>(statusBody, Options);
            if (status?.Implementation != "HostsGuardian.DnsEngine" || status.DnsPort is < 1 or > 65535 || status.ApiPort != cfg.ManagementPort || !IsConsistentStatus(status))
                return new(ConnectionState.Incompatible, "Invalid Engine transport response");
            return result with { Transport = status };
        }
        catch { return new(ConnectionState.Incompatible, "Malformed Engine response"); }
    }
    private static bool IsConsistentStatus(DnsServiceStatus status)
    {
        if (status.RuntimeState is not ("NotStarted" or "Starting" or "Running" or "Degraded" or "Stopping" or "Stopped" or "Faulted")) return false;
        if (status.PolicyRestoreState is not ("NotLoaded" or "Missing" or "Restored" or "Invalid" or "Unavailable")) return false;
        if (status.PersistenceFault is not ("" or "PolicyInvalid" or "PolicyReadFailed" or "PolicyWriteFailed")) return false;
        if (status.SafeModeReason is not ("" or "PolicyNotLoaded" or "UntrustedPolicy" or "ManagementRequested")) return false;
        if (status.LastUpstreamOutcome is not ("NotObserved" or "Response" or "Timeout" or "TransportFailure" or "InvalidResponse" or "Exhausted" or "Truncated" or "ServerFailure")) return false;
        if (status.LastUpstreamFailure is not ("" or "Timeout" or "TransportFailure" or "InvalidResponse" or "Exhausted" or "Truncated" or "ServerFailure")) return false;
        foreach (var listenerState in new[] { status.UdpState, status.TcpState, status.ManagementState })
            if (listenerState is not ("NotStarted" or "Starting" or "Listening" or "Stopped" or "Faulted")) return false;
        if (status.CommittedRuleCount < 0 || status.ActiveRuleCount < 0 || status.PolicyRevision < 0) return false;
        if (status.FilteringEnabled != (status.PolicyLoaded && !status.EmergencySafeMode)) return false;
        if (status.ActiveRuleCount != (status.FilteringEnabled ? status.CommittedRuleCount : 0)) return false;
        if (status.PolicyLoaded && status.PolicyRevision == null) return false;
        if (status.RuntimeState == "Running" && (!status.ManagementListening || !status.UdpListening || !status.TcpListening)) return false;
        if (status.SnapshotUtc != null)
        {
            if (status.UdpListening != (status.UdpState == "Listening")) return false;
            if (status.TcpListening != (status.TcpState == "Listening")) return false;
            if (status.ManagementListening != (status.ManagementState == "Listening")) return false;
        }
        return true;
    }

    // HTTP success is insufficient: the Engine must acknowledge a durable revision and exact count.
    private async Task<PolicyUpdateConfirmation> SendPolicyAsync(DnsEngineConfig cfg, IEnumerable<string> domains, CancellationToken ct)
    {
        var selected = domains.Select(DomainName.Normalize).ToArray();
        if (selected.Any(string.IsNullOrEmpty))
            return new(new(ConnectionState.InvalidSettings, "Invalid selected domain"), null, 0);
        selected = selected.Distinct(StringComparer.Ordinal).ToArray();
        var (result, body) = await Send(cfg, "rules/blocked/replace", JsonSerializer.Serialize(new { blocked = selected }), ct);
        if (!result.Ok) return new(result, null, 0);
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (!root.GetProperty("ok").GetBoolean())
                return new(new(ConnectionState.EngineError, "Engine rejected update"), null, 0);
            var revision = root.GetProperty("revision").GetInt64();
            var count = root.GetProperty("count").GetInt32();
            if (revision < 1 || count != selected.Length) throw new JsonException();
            return new(result, revision, count);
        }
        catch { return new(new(ConnectionState.Incompatible, "Malformed policy confirmation"), null, 0); }
    }

    public Task<SafeModeTransitionResult> EnterSafeModeAsync(DnsEngineConfig cfg, CancellationToken ct = default)
        => ChangeSafeModeAsync(cfg, true, ct);

    public Task<SafeModeTransitionResult> ExitSafeModeAsync(DnsEngineConfig cfg, CancellationToken ct = default)
        => ChangeSafeModeAsync(cfg, false, ct);

    private async Task<SafeModeTransitionResult> ChangeSafeModeAsync(DnsEngineConfig cfg, bool enabled, CancellationToken ct)
    {
        var path = enabled ? "safe-mode/enter" : "safe-mode/exit";
        var (response, body) = await Send(cfg, path, "{}", ct);
        if (!response.Ok) return new(response, enabled, null, null);
        long? revision;
        int count;
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (!root.GetProperty("ok").GetBoolean())
                return new(new(ConnectionState.EngineError, "Safe Mode request rejected"), enabled, null, null);
            var revisionValue = root.GetProperty("revision");
            revision = revisionValue.ValueKind == JsonValueKind.Null ? null : revisionValue.GetInt64();
            count = root.GetProperty("count").GetInt32();
            if (revision < 0 || count < 0 || (revision == null && count != 0)) throw new JsonException();
        }
        catch
        {
            return new(new(ConnectionState.Incompatible, "Malformed Safe Mode acknowledgement"), enabled, null, null);
        }

        // No mutation retry: status may reveal that another operation superseded this request.
        var statusResponse = await TestConnectionAsync(cfg, ct);
        var transition = new SafeModeTransitionResult(statusResponse, enabled, revision, count);
        if (!statusResponse.Ok || transition.Confirmed) return transition;
        return transition with { Connection = new(ConnectionState.EngineError,
            "Safe Mode request acknowledged; current transition unconfirmed") };
    }

    public async Task<PolicyUpdateConfirmation> ReplacePolicyAsync(DnsEngineConfig cfg, IEnumerable<string> domains, CancellationToken ct = default)
    {
        var acknowledgement = await SendPolicyAsync(cfg, domains, ct);
        if (!acknowledgement.Connection.Ok) return acknowledgement;
        var confirmed = await TestConnectionAsync(cfg, ct);
        if (!confirmed.Ok) return acknowledgement with { Connection = confirmed };
        var status = confirmed.Transport;
        if (status == null || status.PolicyRevision != acknowledgement.CommittedRevision ||
            status.CommittedRuleCount != acknowledgement.Count)
            return acknowledgement with { Connection = new(ConnectionState.EngineError,
                "Policy committed; later status differs, synchronization unconfirmed") };
        return acknowledgement with { Connection = confirmed };
    }

    public async Task<(bool ok, string message)> TestAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    { var result = await TestConnectionAsync(cfg, ct); return (result.Ok, result.Message); }

    // Compatibility callers get a validated acknowledgement, not a claim of current synchronization.
    public async Task<(bool ok, string message)> PushBlockedDomainsAsync(DnsEngineConfig cfg, IEnumerable<string> domains, CancellationToken ct = default)
    {
        var result = await SendPolicyAsync(cfg, domains, ct);
        return (result.Connection.Ok, result.Connection.Ok
            ? $"DNS policy commit acknowledged at revision {result.CommittedRevision}" : result.Connection.Message);
    }

    public async Task<(bool ok, string message, string[] blocked)> GetBlockedDomainsAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var (result, body) = await Send(cfg, "rules/blocked", null, ct);
        if (!result.Ok) return (false, result.Message, Array.Empty<string>());
        try { using var doc = JsonDocument.Parse(body); return (true, "Rules read", doc.RootElement.GetProperty("blocked").EnumerateArray().Select(x => x.GetString()!).ToArray()); }
        catch { return (false, "Malformed Engine response", Array.Empty<string>()); }
    }
    public async Task<(bool ok, string message)> GetDnsStatusAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var result = await TestConnectionAsync(cfg, ct);
        return (result.Ok, result.Transport == null ? result.Message : $"UDP: {(result.Transport.UdpListening ? "listening" : "stopped")} :{result.Transport.DnsPort}; TCP: {(result.Transport.TcpListening ? "listening" : "stopped")}");
    }
}
