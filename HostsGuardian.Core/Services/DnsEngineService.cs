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
    private ClassificationReadModel _classificationReadModel=new();
    private string _classificationScope="";
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
    public async Task<(ConnectionResult Connection, OperationalEventBatch? Batch)> ReadOperationalEventsAsync(DnsEngineConfig cfg, long after = 0, CancellationToken ct = default)
    {
        if (after < 0) throw new ArgumentOutOfRangeException(nameof(after));
        var (result, body) = await Send(cfg, "v2/operational-events?after=" + after.ToString(System.Globalization.CultureInfo.InvariantCulture), null, ct);
        if (!result.Ok) return (result, null);
        try
        {
            var batch = JsonSerializer.Deserialize<OperationalEventBatch>(body, Options);
            if (batch == null || batch.SchemaVersion != 1 || string.IsNullOrWhiteSpace(batch.InstanceId) || batch.InstanceId.Length > 100 ||
                batch.LatestSequence < 0 || batch.Events == null || batch.Events.Length > 64 || batch.Components == null || batch.Components.Length != 6)
                throw new JsonException();
            var components = new HashSet<string> { "Listeners", "Management", "Upstream", "Processing", "Capacity", "Persistence" };
            foreach (var c in batch.Components)
                if (!components.Remove(c.Component) || c.State is not ("Healthy" or "Degraded" or "Critical") ||
                    (c.State != "Healthy" && string.IsNullOrWhiteSpace(c.IncidentId)) || c.IncidentId?.Length > 160) throw new JsonException();
            long sequence = 0;
            foreach (var e in batch.Events)
            {
                if (e.Sequence <= sequence || e.Sequence > batch.LatestSequence || e.InstanceId != batch.InstanceId ||
                    e.Severity is not ("Warning" or "Critical" or "Recovery") || e.State is not ("Healthy" or "Degraded" or "Critical") ||
                    string.IsNullOrWhiteSpace(e.IncidentId) || e.IncidentId.Length > 160 || e.Type.Length > 80 || e.SummaryId.Length > 100)
                    throw new JsonException();
                sequence = e.Sequence;
            }
            return (result, batch);
        }
        catch { return (new(ConnectionState.Incompatible, "Invalid operational event contract"), null); }
    }
    public async Task<(ConnectionResult Connection, ProductActivityRead? Activity)> ReadActivityAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var (connection, body) = await Send(cfg, "v3/activity", null, ct);
        if (!connection.Ok) return (connection,null);
        try
        {
            var read=JsonSerializer.Deserialize<ProductActivityRead>(body, Options);
            if(read==null || read.SchemaVersion!=1 || read.Buckets==null || read.Buckets.Length>256 || read.RetentionHours!=24 || read.MaximumBuckets!=256 ||
               read.Buckets.Any(b=>b==null || b.Allowed<0 || b.Blocked<0 || b.Failed<0 || b.ServiceName==null || b.ServiceName.Length>128 ||
               b.WindowStartUtc>read.ObservedAtUtc || b.WindowStartUtc<read.ObservedAtUtc.AddHours(-24).AddMinutes(-5)))throw new JsonException();
            return(connection,read);
        }
        catch{return(new(ConnectionState.Incompatible,"Invalid activity contract"),null);}
    }

    public async Task<(ConnectionResult Connection, PolicyAuditRead? Audit)> ReadPolicyAuditAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var (connection, body) = await Send(cfg, "v3/policy-audit", null, ct);
        if (!connection.Ok) return (connection, null);
        try
        {
            var read = JsonSerializer.Deserialize<PolicyAuditRead>(body, Options);
            if (read == null || read.SchemaVersion != 1 || read.MaximumEntries != 1000 || read.Entries == null || read.Entries.Length > 100 ||
                read.Entries.Any(r => r == null || r.Operation == null || r.Operation.Length > 80 ||
                    r.ActorEvidence == null || r.ActorEvidence.Length > 160 || r.Outcome == null || r.Outcome.Length > 80 ||
                    r.PolicyHash == null || r.PolicyHash.Length != 64 || r.PolicyHash.Any(c => !Uri.IsHexDigit(c)) ||
                    r.Changes == null || r.Changes.Length > 1024 || r.PreviousRevision < 0 || r.EffectiveRevision < 0)) throw new JsonException();
            return (connection, read);
        }
        catch { return (new(ConnectionState.Incompatible, "Invalid policy audit contract"), null); }
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
        var read = await ReadFullPolicyAsync(cfg, ct);
        if (!read.Connection.Ok || read.Policy == null) return new(read.Connection, null, 0);
        FullDnsPolicy outgoing;
        try
        {
            outgoing = PolicyCanonicalization.Canonicalize(read.Policy.Policy with
            { GlobalBlockedDomains = System.Collections.Immutable.ImmutableArray.CreateRange(domains) });
        }
        catch { return new(new(ConnectionState.InvalidSettings, "Invalid policy"), null, 0); }
        var full = await ReplaceFullPolicyAsync(cfg, new(read.Policy.Revision, outgoing, read.Policy.InstanceId), ct);
        return new(full.Connection, full.AcknowledgedRevision, outgoing.GlobalBlockedDomains.Length);
    }

    private static readonly JsonSerializerOptions FullOptions = new()
    { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
      UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };

    public async Task<(ConnectionResult Connection, FullPolicyRead? Policy)> ReadFullPolicyAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var (result, body) = await Send(cfg, "v2/policy", null, ct);
        if (!result.Ok) return (result, null);
        try
        {
            var read = JsonSerializer.Deserialize<FullPolicyRead>(body, FullOptions);
            if (read == null || read.Policy.SchemaVersion is not (2 or 3) || read.Policy.Devices.IsDefault || read.Policy.Overrides.IsDefault
                || read.Policy.GlobalBlockedDomains.IsDefault || read.Revision < 0 || string.IsNullOrWhiteSpace(read.InstanceId)) throw new JsonException();
            var canonical = PolicyCanonicalization.Canonicalize(read.Policy);
            if (JsonSerializer.Serialize(canonical, FullOptions) != JsonSerializer.Serialize(read.Policy, FullOptions)) throw new JsonException();
            return (result, read);
        }
        catch { return (new(ConnectionState.Incompatible, "Malformed full-policy response"), null); }
    }

    public async Task<FullPolicyConfirmation> ReplaceFullPolicyAsync(DnsEngineConfig cfg, FullPolicyReplace request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.ExpectedInstanceId)) return new(new(ConnectionState.InvalidSettings, "Read Engine instance before replacing policy"), null, false);
        var (capabilityResult, capabilities) = await Send(cfg, "v2/capabilities", null, ct);
        if (!capabilityResult.Ok) return new(capabilityResult, null, false);
        try
        {
            using var document = JsonDocument.Parse(capabilities);
            if (request.Policy.SchemaVersion == 3 && (!document.RootElement.TryGetProperty("supportedPolicySchemas", out var schemas) ||
                !schemas.EnumerateArray().Any(v => v.GetInt32() == 3))) throw new JsonException();
            if (document.RootElement.GetProperty("policySchemaVersion").GetInt32() != 2
                || !document.RootElement.GetProperty("fullPolicyReadback").GetBoolean()
                || !document.RootElement.GetProperty("optimisticConcurrency").GetBoolean()) throw new JsonException();
        }
        catch { return new(new(ConnectionState.Incompatible, "Full-policy capabilities required"), null, false); }
        var (result, acknowledgement) = await Send(cfg, "v2/policy/replace", JsonSerializer.Serialize(request, FullOptions), ct);
        if (!result.Ok) return new(result, null, false);
        long revision;
        try
        {
            using var document = JsonDocument.Parse(acknowledgement);
            if (!document.RootElement.GetProperty("ok").GetBoolean()) throw new JsonException();
            revision = document.RootElement.GetProperty("revision").GetInt64();
            if (revision < 1) throw new JsonException();
        }
        catch { return new(new(ConnectionState.Incompatible, "Malformed policy acknowledgement"), null, false); }
        var read = await ReadFullPolicyAsync(cfg, ct);
        if (!read.Connection.Ok) return new(read.Connection, null, false, revision);
        if (read.Policy?.Revision != revision || read.Policy.InstanceId != request.ExpectedInstanceId || JsonSerializer.Serialize(read.Policy.Policy, FullOptions) != JsonSerializer.Serialize(request.Policy, FullOptions))
            return new(new(ConnectionState.EngineError, "Full policy differs; synchronization unconfirmed"), read.Policy, false, revision);
        var status = await TestConnectionAsync(cfg, ct);
        return new(status, read.Policy, true, revision);
    }

    public async Task<(ConnectionResult Connection, EffectivePolicyExplanation? Explanation)> ExplainPolicyAsync(
        DnsEngineConfig cfg, string address, string domain, CancellationToken ct = default)
    {
        if (!System.Net.IPAddress.TryParse(address, out _) || DomainName.Normalize(domain) == "")
            return (new(ConnectionState.InvalidSettings, "Select an observed address and domain"), null);
        var (result, body) = await Send(cfg, "v2/effective-policy?address=" + Uri.EscapeDataString(address)
            + "&domain=" + Uri.EscapeDataString(domain), null, ct);
        if (!result.Ok) return (result, null);
        try
        {
            var explanation = JsonSerializer.Deserialize<EffectivePolicyExplanation>(body, FullOptions);
            if (explanation == null || explanation.Domain != DomainName.Normalize(domain) || explanation.DecisionChain.IsDefault || explanation.DecisionChain.Length > 128 ||
                explanation.DecisionChain.Any(r => r == null || !Enum.IsDefined(r.Layer) || !Enum.IsDefined(r.State) ||
                    r.State == DeviceDomainRuleState.Inherit || r.Domain != DomainName.Normalize(r.Domain) || !PolicyDecision.Matches(explanation.Domain, r.Domain) ||
                    r.Source is not ("GlobalBlock" or "GlobalAllow" or "GroupRule" or "ActiveProfile" or "ActiveSchedule" or "DeviceOverride")) ||
                (explanation.Winner != null && (explanation.DecisionChain.IsEmpty || explanation.DecisionChain[0] != explanation.Winner ||
                    explanation.Blocked != (explanation.Winner.State == DeviceDomainRuleState.Block)))) throw new JsonException();
            return (result, explanation);
        }
        catch { return (new(ConnectionState.Incompatible, "Malformed policy explanation"), null); }
    }

    public async Task<LanDeviceObservation[]> ReadLanDiscoveryAsync(DnsEngineConfig cfg,CancellationToken ct=default)
    {
        var (result,body)=await Send(cfg,"v2/discovery",null,ct);if(!result.Ok)return [];
        try
        {
            var rows=JsonSerializer.Deserialize<LanDeviceObservation[]>(body,FullOptions);
            if(rows==null || rows.Length>64 || rows.Any(r=>r==null || r.ObservationDeviceId==Guid.Empty || r.Presence!="OBSERVED" ||
                r.Coverage is not ("UNKNOWN" or "PARTIAL") || r.ResolverPath!="UNKNOWN" || r.DnsActivity is not ("OBSERVED" or "NOT OBSERVED") ||
                r.Evidence==null || r.Evidence.Length is <1 or >8 || r.Evidence.Any(e=>e==null || !System.Net.IPAddress.TryParse(e.Address,out _) ||
                    e.Mac==null || e.Mac.Length>32 || e.Hostname==null || e.Hostname.Length>128 || e.Hostname.Any(char.IsControl) ||
                    e.Provenance==null || e.Provenance.Length>160 || e.Provenance.Any(char.IsControl)))) throw new JsonException();
            var scope=cfg.BaseUrl+"|"+cfg.CredentialId;
            if(scope!=_classificationScope){_classificationReadModel=new();_classificationScope=scope;}
            return rows.Select(row=>_classificationReadModel.Apply(row,DateTimeOffset.UtcNow)).ToArray();
        }
        catch {return [];}
    }
    public async Task<(ConnectionResult Connection, NetworkIdentityEvidence[]? Evidence)> ReadIdentityEvidenceAsync(DnsEngineConfig cfg, CancellationToken ct=default, bool refresh=false)
    {
        var (result,body)=await Send(cfg,refresh?"v2/discovery/refresh":"v2/identity-evidence",refresh?"{}":null,ct);
        if(!result.Ok) return (result,null);
        try
        {
            var rows=JsonSerializer.Deserialize<NetworkIdentityEvidence[]>(body,FullOptions);
            if(rows==null || rows.Length>64 || rows.Any(r=>r==null || !System.Net.IPAddress.TryParse(r.Address,out _) || r.Mac==null || r.Mac.Length>32 || r.Hostname==null || r.Hostname.Length>128 || r.Provenance==null || r.Provenance.Length>160 ||
                r.Hostname.Any(char.IsControl) || r.Provenance.Any(char.IsControl) || (r.ReadAtUtc ?? r.ObservedAtUtc)<DateTimeOffset.UtcNow.AddMinutes(-1) || r.ObservedAtUtc>DateTimeOffset.UtcNow.AddSeconds(30))) throw new JsonException();
            return (result,rows);
        }
        catch { return (new(ConnectionState.Incompatible,"Malformed identity evidence"),null); }
    }
    public async Task<(ConnectionResult Connection, BindingRead? Bindings)> ReadBindingsAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    {
        var (result, body) = await Send(cfg, "v2/bindings", null, ct);
        if (!result.Ok) return (result, null);
        try
        {
            var read = JsonSerializer.Deserialize<BindingRead>(body, FullOptions);
            if (read == null || read.Generation < 0 || read.Observations.IsDefault) throw new JsonException();
            return (result, read);
        }
        catch { return (new(ConnectionState.Incompatible, "Malformed binding response"), null); }
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
