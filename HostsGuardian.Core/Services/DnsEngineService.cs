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
        var token = string.IsNullOrEmpty(cfg.ApiToken) ? _credentials.Read(cfg.CredentialId) : cfg.ApiToken;
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
            if (status?.Implementation != "HostsGuardian.DnsEngine" || status.DnsPort is < 1 or > 65535 || status.ApiPort != cfg.ManagementPort)
                return new(ConnectionState.Incompatible, "Invalid Engine transport response");
            return result with { Transport = status };
        }
        catch { return new(ConnectionState.Incompatible, "Malformed Engine response"); }
    }
    public async Task<(bool ok, string message)> TestAsync(DnsEngineConfig cfg, CancellationToken ct = default)
    { var result = await TestConnectionAsync(cfg, ct); return (result.Ok, result.Message); }
    public async Task<(bool ok, string message)> PushBlockedDomainsAsync(DnsEngineConfig cfg, IEnumerable<string> domains, CancellationToken ct = default)
    {
        var list = domains.Select(DomainName.Normalize).ToArray();
        if (list.Any(string.IsNullOrEmpty)) return (false, "Invalid selected domain");
        var (result, body) = await Send(cfg, "rules/blocked/replace", JsonSerializer.Serialize(new { blocked = list.Distinct().ToArray() }), ct);
        if (!result.Ok) return (false, result.Message);
        try { using var doc = JsonDocument.Parse(body); if (!doc.RootElement.GetProperty("ok").GetBoolean()) return (false, "Engine rejected update"); }
        catch { return (false, "Malformed Engine response"); }
        return (true, "Explicit DNS rules sent");
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
        return (result.Ok, result.Transport == null ? result.Message : $"UDP: {(result.Transport.UdpListening ? "listening" : "stopped")} :{result.Transport.DnsPort}; TCP: {(result.Transport.TcpImplemented ? "implemented" : "not implemented")}");
    }
}
