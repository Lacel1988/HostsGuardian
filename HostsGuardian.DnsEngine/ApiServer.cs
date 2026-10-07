using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace HostsGuardian.DnsEngine;

public sealed class ApiServer : IAsyncDisposable
{
    private const int MaximumRequestBodyBytes = 65536;
    private readonly PolicyApplicationService _policy;
    private readonly AddressBindingStore _bindings;
    private readonly DnsObservationStore _observations;
    private readonly ProductActivityStore _activity;
    private readonly IEngineRuntimeStatus _runtimeStatus;
    private readonly EngineSettings _settings;
    private readonly EngineConfig? _legacyConfig;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private WebApplication? _application;
    private X509Certificate2? _certificate;
    private byte[]? _credential;
    private int _running;
    private TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenRegistration _stoppedRegistration;
    internal Task Completion => _completion.Task;

    public bool IsRunning => Volatile.Read(ref _running) == 1;

    // Compatibility for existing callers: security input may be corrected before a startup retry.
    public ApiServer(RuleStore rules, EngineConfig config, DnsProxyServer dns)
        : this(new PolicyApplicationService(rules, new PolicyPersistence(config.PolicyFilePath), dns.PolicyState), EngineSettings.FromConfig(config), dns.RuntimeStatus, dns.RequestProcessor.Bindings, dns.RequestProcessor.Observations, dns.RequestProcessor.Activity)
    {
        _legacyConfig = config;
    }

    public ApiServer(PolicyApplicationService policy, EngineSettings settings, IEngineRuntimeStatus runtimeStatus, AddressBindingStore? bindings = null, DnsObservationStore? observations = null, ProductActivityStore? activity = null)
    {
        _bindings = bindings ?? new AddressBindingStore();
        _observations = observations ?? new DnsObservationStore();
        _activity = activity ?? new ProductActivityStore();
        _policy = policy;
        _settings = settings;
        _runtimeStatus = runtimeStatus;
    }

    public void Start() => StartAsync().GetAwaiter().GetResult();
    public void Stop() => StopAsync().GetAwaiter().GetResult();
    public void InitializePolicyForStartup() => _policy.InitializeForStartup();

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsRunning) return;
            InitializePolicyForStartup();
            if (_runtimeStatus is EngineRuntimeStatus startingStatus) startingStatus.SetManagementState("Starting");
            var settings = _legacyConfig == null ? _settings : EngineSettings.FromConfig(_legacyConfig);
            byte[]? credential = null;
            X509Certificate2? certificate = null;
            WebApplication? application = null;
            try
            {
                credential = LoadCredential(settings.CredentialPath);
                certificate = LoadCertificate(settings);
                application = BuildApplication(settings, certificate, credential);
                await application.StartAsync(cancellationToken).ConfigureAwait(false);
                _application = application;
                _certificate = certificate;
                _credential = credential;
                Volatile.Write(ref _running, 1);
                if (_runtimeStatus is EngineRuntimeStatus status) status.SetManagementListening(true);
                _completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _stoppedRegistration = application.Lifetime.ApplicationStopped.Register(() =>
                {
                    Volatile.Write(ref _running, 0);
                    if (_runtimeStatus is EngineRuntimeStatus stoppedStatus) stoppedStatus.SetManagementListening(false);
                    _completion.TrySetResult();
                });
                EngineLog.Information("Management", $"HTTPS listening on {settings.ApiAddress}:{settings.ApiPort}");
            }
            catch
            {
                try
                {
                    if (application != null) await application.DisposeAsync().ConfigureAwait(false);
                }
                finally
                {
                    certificate?.Dispose();
                    if (credential != null) CryptographicOperations.ZeroMemory(credential);
                }
                if (_runtimeStatus is EngineRuntimeStatus failedStatus) failedStatus.SetManagementState("Faulted");
                EngineLog.Failure("Management", "Security configuration or listener startup failed");
                throw;
            }
        }
        finally { _lifecycleGate.Release(); }
    }

    private WebApplication BuildApplication(EngineSettings settings, X509Certificate2 certificate, byte[] credential)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
        // Retain Phase 4's prohibition on automatic request/header/body diagnostics.
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestBodySize = MaximumRequestBodyBytes;
            server.Limits.MaxRequestHeadersTotalSize = 16384;
            server.Listen(settings.ApiAddress, settings.ApiPort, endpoint => endpoint.UseHttps(certificate));
        });
        var application = builder.Build();
        application.Run(context => HandleAuthenticatedRequestAsync(context, credential));
        return application;
    }

    private static X509Certificate2 LoadCertificate(EngineSettings settings)
    {
        X509Certificate2 certificate;
        try
        {
            using var pem = X509Certificate2.CreateFromPemFile(settings.CertificatePath, settings.CertificateKeyPath);
            // Windows Schannel requires a PKCS#12-backed private key for PEM-loaded certificates.
            certificate = OperatingSystem.IsWindows()
                ? new X509Certificate2(pem.Export(X509ContentType.Pkcs12))
                : new X509Certificate2(pem);
        }
        catch { throw new InvalidOperationException("Management certificate unavailable"); }

        try
        {
            var now = DateTime.UtcNow;
            if (!certificate.HasPrivateKey || now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime())
                throw new InvalidOperationException("Invalid management certificate");
            var usage = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            var permitsServerAuthentication = usage != null && usage.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1");
            if (!permitsServerAuthentication)
                throw new InvalidOperationException("Management certificate is not valid for server authentication");
            return certificate;
        }
        catch { certificate.Dispose(); throw; }
    }

    public static byte[] LoadCredential(EngineConfig config) => LoadCredential(config.CredentialPath);

    private static byte[] LoadCredential(string path)
    {
        string value;
        try { value = File.ReadAllText(path).TrimEnd('\r', '\n'); }
        catch { throw new InvalidOperationException("Management credential unavailable"); }
        return ManagementSecurity.ParseToken(value) ?? throw new InvalidOperationException("Invalid management credential");
    }

    public async Task StopAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            try
            {
                if (_application != null)
                {
                    // Bound graceful HTTPS shutdown; disposal still runs if stopping fails.
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    try { await _application.StopAsync(deadline.Token).ConfigureAwait(false); }
                    finally { await _application.DisposeAsync().ConfigureAwait(false); }
                }
            }
            finally
            {
                _stoppedRegistration.Dispose();
                _completion.TrySetResult();
                _application = null;
                _certificate?.Dispose();
                _certificate = null;
                if (_credential != null) CryptographicOperations.ZeroMemory(_credential);
                _credential = null;
                var wasRunning = Interlocked.Exchange(ref _running, 0) == 1;
                if (_runtimeStatus is EngineRuntimeStatus status) status.SetManagementListening(false);
                if (wasRunning) EngineLog.Information("Management", "HTTPS stopped");
            }
        }
        finally { _lifecycleGate.Release(); }
    }

    private async Task HandleAuthenticatedRequestAsync(HttpContext context, byte[] credential)
    {
        if (!ManagementSecurity.Authorize(context.Request.Headers.Authorization.ToArray()!, credential))
        {
            await WriteErrorAsync(context, 401, "Unauthorized");
            return;
        }
        try { await DispatchAsync(context); }
        catch (BadHttpRequestException) { await WriteErrorAsync(context, 413, "Request rejected"); }
        catch (Exception exception) when (exception is JsonException or ArgumentException)
        { await WriteErrorAsync(context, 400, "Invalid request"); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
        catch (Exception)
        {
            EngineLog.Failure("Management", "Protected operation failed");
            await WriteErrorAsync(context, 500, "Engine error");
        }
    }

    private static Task WriteErrorAsync(HttpContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        return context.Response.WriteAsJsonAsync(new { error = message });
    }

    private async Task DispatchAsync(HttpContext context)
    {
        var path = context.Request.Path.Value?.TrimEnd('/') ?? "";
        if (context.Request.Method == "GET" && await HandleReadAsync(context, path)) return;
        if (context.Request.Method == "POST" && path == "/v2/policy/replace")
        {
            using var document = await ReadRequestDocumentAsync(context);
            if (!document.RootElement.TryGetProperty("expectedRevision", out _)) throw new ArgumentException();
            var request = document.RootElement.Deserialize<FullPolicyReplace>(PolicyPersistence.JsonOptions) ?? throw new ArgumentException();
            if (string.IsNullOrWhiteSpace(request.ExpectedInstanceId)) throw new ArgumentException();
            await WritePolicyResultAsync(context, _policy.ReplaceFull(request), false);
            return;
        }
        if (context.Request.Method == "POST" && path == "/v2/bindings/replace")
        {
            using var document = await ReadRequestDocumentAsync(context);
            if (!document.RootElement.TryGetProperty("expectedGeneration", out _)) throw new ArgumentException();
            var request = document.RootElement.Deserialize<BindingReplace>(PolicyPersistence.JsonOptions) ?? throw new ArgumentException();
            if (!_bindings.Replace(request)) { await WriteErrorAsync(context, 409, "Mapping generation conflict"); return; }
            await context.Response.WriteAsJsonAsync(_bindings.Read());
            return;
        }
        if (context.Request.Method == "POST" && path == "/v2/discovery/refresh")
        {
            using var document=await ReadRequestDocumentAsync(context);
            if(document.RootElement.EnumerateObject().Any())throw new ArgumentException();
            var networkRefresh=HostsGuardian.Core.Services.LanDiscoveryRefresh.RefreshAsync(context.RequestAborted);
            await Task.WhenAll(networkRefresh,HostsGuardian.Core.Services.FingerprintDiscovery.RefreshAsync(context.RequestAborted));
            var observations=await networkRefresh;
            HostsGuardian.Core.Services.LanObservationStore.Shared.Observe(observations,DateTimeOffset.UtcNow);
            await context.Response.WriteAsJsonAsync(observations);
            return;
        }
        if (context.Request.Method == "POST" && path is "/safe-mode/enter" or "/safe-mode/exit")
        {
            using var document = await ReadRequestDocumentAsync(context);
            if (document.RootElement.EnumerateObject().Any()) throw new ArgumentException();
            var result = _policy.SetSafeMode(path == "/safe-mode/enter");
            await WritePolicyResultAsync(context, result, includeRemoved: false);
            return;
        }
        if (context.Request.Method == "POST" && path.StartsWith("/rules/blocked/", StringComparison.Ordinal))
        {
            using var document = await ReadRequestDocumentAsync(context);
            if (await HandleMutationAsync(context, path, document.RootElement)) return;
        }
        context.Response.StatusCode = 404;
    }

    private async Task<bool> HandleReadAsync(HttpContext context, string path)
    {
        switch (path)
        {
            case "":
            case "/health":
                await context.Response.WriteAsJsonAsync(new { ok = true, engine = "HostsGuardian.DnsEngine", apiVersion = 1 });
                return true;
            case "/v2/identity-evidence":
                await context.Response.WriteAsJsonAsync(HostsGuardian.Core.Services.PassiveIdentityEvidence.Read());
                return true;
            case "/v2/discovery":
                var lan=(_runtimeStatus as EngineRuntimeStatus)?.Diagnostics?.Snapshot().Devices?.LanDevices ??
                    HostsGuardian.Core.Services.LanObservationStore.Shared.Observe(HostsGuardian.Core.Services.PassiveIdentityEvidence.Read(),DateTimeOffset.UtcNow);
                await context.Response.WriteAsJsonAsync(lan);
                return true;
            case "/v2/diagnostics":
                if ((_runtimeStatus as EngineRuntimeStatus)?.Diagnostics is not { } diagnostics) { context.Response.StatusCode = 404; return true; }
                await context.Response.WriteAsJsonAsync(diagnostics.Snapshot()); return true;
            case "/v2/operational-events":
                if ((_runtimeStatus as EngineRuntimeStatus)?.Diagnostics is not { } events) { context.Response.StatusCode = 404; return true; }
                var cursor = context.Request.Query["after"].ToString();
                if (cursor != "" && (!long.TryParse(cursor, out _) || long.Parse(cursor) < 0)) throw new ArgumentException();
                await context.Response.WriteAsJsonAsync(events.Health.Read(cursor == "" ? 0 : long.Parse(cursor))); return true;
            case "/v3/activity":
                await context.Response.WriteAsJsonAsync(_activity.Read(DateTimeOffset.UtcNow)); return true;
            case "/v3/policy-audit":
                var audit = _policy.Audit.Read();
                await context.Response.WriteAsJsonAsync(new { schemaVersion = 1, available = _policy.Audit.Available,
                    maximumEntries = PolicyAuditStore.MaximumEntries, entries = audit.TakeLast(100).Reverse().ToArray() }); return true;
            case "/v2/dns-observations":
                await context.Response.WriteAsJsonAsync(new { capacity = 64, observations = _observations.Read() });
                return true;
            case "/v2/capabilities":
                await context.Response.WriteAsJsonAsync(new { apiVersion = 2, policySchemaVersion = 2, supportedPolicySchemas = new[] { 2, 3 },
                    ipv4DeviceEnforcement = true, ipv6DeviceEnforcement = false, scopedBindings = true,
                    fullPolicyReadback = true, optimisticConcurrency = true });
                return true;
            case "/v2/policy":
                await context.Response.WriteAsJsonAsync(_policy.ReadFullPolicy());
                return true;
            case "/v2/bindings":
                await context.Response.WriteAsJsonAsync(_bindings.Read());
                return true;
            case "/v2/effective-policy":
                var address = context.Request.Query["address"].ToString();
                var domain = context.Request.Query["domain"].ToString();
                if (!IPAddress.TryParse(address, out _) || DomainName.Normalize(domain) == "") throw new ArgumentException();
                var scope = context.Request.Query["scope"].ToString();
                var snapshot = _policy.State.GetSnapshot();
                await context.Response.WriteAsJsonAsync(DevicePolicyEvaluator.Explain(snapshot, snapshot.Policy ?? FullDnsPolicy.Empty,
                    _bindings.Read(), new(DnsTransport.Udp, address, 0, DateTimeOffset.UtcNow, scope == "" ? null : scope), domain, DateTimeOffset.UtcNow));
                return true;
            case "/dns/status":
                await context.Response.WriteAsJsonAsync(GetDnsStatus());
                return true;
            case "/rules/blocked":
                var policy = _policy.ReadPolicy();
                await context.Response.WriteAsJsonAsync(new { ok = true, blocked = policy.Domains, revision = policy.Revision });
                return true;
            default:
                return false;
        }
    }

    private static async Task<JsonDocument> ReadRequestDocumentAsync(HttpContext context)
    {
        if (context.Request.ContentLength > MaximumRequestBodyBytes)
            throw new BadHttpRequestException("Request too large", 413);
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = await context.Request.Body.ReadAsync(buffer, context.RequestAborted)) > 0)
        {
            if (memory.Length + bytesRead > MaximumRequestBodyBytes)
                throw new BadHttpRequestException("Request too large", 413);
            await memory.WriteAsync(buffer.AsMemory(0, bytesRead), context.RequestAborted);
        }
        var document = JsonDocument.Parse(memory.ToArray());
        try
        {
            var root = document.RootElement;
            PolicyPersistence.RejectDuplicateProperties(root);
            if (root.ValueKind != JsonValueKind.Object) throw new ArgumentException();
            var propertyNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!propertyNames.Add(property.Name)) throw new ArgumentException();
            return document;
        }
        catch { document.Dispose(); throw; }
    }

    private async Task<bool> HandleMutationAsync(HttpContext context, string path, JsonElement root)
    {
        if (path is "/rules/blocked/replace" or "/rules/blocked/add")
        {
            var replace = path == "/rules/blocked/replace";
            var domains = ReadDomainList(root, replace ? "blocked" : "domains");
            var result = replace ? _policy.Replace(domains) : _policy.Add(domains);
            await WritePolicyResultAsync(context, result, includeRemoved: false);
            return true;
        }
        if (path == "/rules/blocked/remove")
        {
            if (!root.TryGetProperty("domain", out var value) || value.ValueKind != JsonValueKind.String)
                throw new ArgumentException();
            var domain = value.GetString()!;
            if (DomainName.Normalize(domain) == "") throw new ArgumentException();
            var result = _policy.Remove(domain);
            await WritePolicyResultAsync(context, result, includeRemoved: true);
            return true;
        }
        return false;
    }

    private static string[] ReadDomainList(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var list) || list.ValueKind != JsonValueKind.Array)
            throw new ArgumentException();
        var domains = new List<string>();
        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) throw new ArgumentException();
            domains.Add(item.GetString()!);
        }
        return domains.ToArray();
    }

    public DnsServiceStatus GetDnsStatus() => _runtimeStatus.GetSnapshot();
    private static Task WritePolicyResultAsync(HttpContext context, PolicyApplicationResult result, bool includeRemoved)
    {
        if (!result.Success)
        {
            context.Response.StatusCode = result.FailureCategory switch
            {
                "InvalidPolicy" => 400,
                "RestoreFault" or "NotLoaded" or "RevisionExhausted" or "RevisionConflict" or "InstanceConflict" => 409,
                _ => 503
            };
            return context.Response.WriteAsJsonAsync(new { ok = false, error = result.Message,
                category = result.FailureCategory, revision = result.Revision, count = result.Count });
        }
        if (includeRemoved)
            return context.Response.WriteAsJsonAsync(new { ok = true, removed = result.Removed, revision = result.Revision, count = result.Count });
        return context.Response.WriteAsJsonAsync(new { ok = true, revision = result.Revision, count = result.Count });
    }
    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
