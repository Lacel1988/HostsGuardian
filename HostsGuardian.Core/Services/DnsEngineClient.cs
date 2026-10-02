using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
public sealed class DnsEngineClient
{
    private readonly DnsEngineService _service;
    public DnsEngineClient(HttpClient? http = null, ICredentialStore? credentials = null)
        => _service = new DnsEngineService(http == null ? null : () => new HttpClient(new BorrowedHandler(http)), credentials);
    public Task<(bool ok, string message)> TestHealthAsync(DnsEngineConfig cfg, CancellationToken ct = default) => _service.TestAsync(cfg, ct);
    public Task<(bool ok, string message)> PushDomainsAsync(DnsEngineConfig cfg, AppConfig app, CancellationToken ct = default)
        => _service.PushBlockedDomainsAsync(cfg, DomainPolicySelection.ForDns(app.BlockedDomains), ct);
    private sealed class BorrowedHandler(HttpClient http) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var copy = new HttpRequestMessage(request.Method, request.RequestUri);
            foreach (var header in request.Headers) copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
            if (request.Content != null)
            {
                copy.Content = new ByteArrayContent(await request.Content.ReadAsByteArrayAsync(cancellationToken));
                foreach (var header in request.Content.Headers) copy.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            return await http.SendAsync(copy, cancellationToken);
        }
    }
}
