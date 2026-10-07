using System.Runtime.InteropServices;
using HostsGuardian.DnsEngine;

using var shutdown = new CancellationTokenSource();
ConsoleCancelEventHandler cancelHandler = (_, args) =>
{
    args.Cancel = true;
    shutdown.Cancel();
};
Console.CancelKeyPress += cancelHandler;
using var terminate = OperatingSystem.IsLinux()
    ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
    {
        context.Cancel = true;
        shutdown.Cancel();
    })
    : null;

try
{
    var credentialsDirectory = Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY");
    var config = new EngineConfig
    {
        ApiBindIp = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_API_BIND") ?? "127.0.0.1",
        UpstreamDnsIpv4 = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_UPSTREAM_ADDRESS") ?? new EngineConfig().UpstreamDnsIpv4,
        UpstreamDnsPort = ReadIntegerEnvironment("HOSTSGUARDIAN_UPSTREAM_PORT", 53),
        FallbackDnsIpv4 = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_FALLBACK_ADDRESS") ?? "",
        FallbackDnsPort = ReadIntegerEnvironment("HOSTSGUARDIAN_FALLBACK_PORT", 53),
        UpstreamTimeoutMs = ReadIntegerEnvironment("HOSTSGUARDIAN_UPSTREAM_TIMEOUT_MS", 2500),
        UpstreamRetryCount = ReadIntegerEnvironment("HOSTSGUARDIAN_UPSTREAM_RETRY_COUNT", 1),
        MaxConcurrentUdpRequests = ReadIntegerEnvironment("HOSTSGUARDIAN_UDP_CONCURRENCY", 16),
        CredentialPath = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_CREDENTIAL_FILE")
            ?? (credentialsDirectory == null ? "" : Path.Combine(credentialsDirectory, "management-token")),
        CertificatePath = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_CERTIFICATE_FILE") ?? "",
        CertificateKeyPath = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_CERTIFICATE_KEY_FILE") ?? "",
        PolicyFilePath = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_POLICY_FILE")
            ?? new EngineConfig().PolicyFilePath
    };
    var settings = EngineSettings.FromConfig(config);
    var rules = new RuleStore(Guid.NewGuid().ToString("N")[..8]);
    await using var dns = new DnsProxyServer(rules, settings);
    var policy = new PolicyApplicationService(rules, new PolicyPersistence(settings.PolicyFilePath), dns.PolicyState);
    await using var api = new ApiServer(policy, settings, dns.RuntimeStatus, dns.RequestProcessor.Bindings, dns.RequestProcessor.Observations, dns.RequestProcessor.Activity);
    var monitorPath = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_MONITOR_STATUS_FILE");
    var bindingProducer=new ValidatedBindingProducer(dns.RequestProcessor.Bindings,
        ()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,
        HostsGuardian.Core.Services.PassiveIdentityEvidence.ReadBindingEvidence);
    var validatorSocket=Environment.GetEnvironmentVariable("HOSTSGUARDIAN_VALIDATOR_SOCKET");
    var activeEnabled=Environment.GetEnvironmentVariable("HOSTSGUARDIAN_ACTIVE_VALIDATION")=="1";
    var activeProducer=string.IsNullOrEmpty(validatorSocket)?null:new ActiveBindingProducer(dns.RequestProcessor.Bindings,
        ()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,
        HostsGuardian.Core.Services.PassiveIdentityEvidence.ReadBindingEvidence,new NetworkValidatorClient(validatorSocket),activeValidationEnabled:activeEnabled);
    var monitor = monitorPath == null ? null : new LocalMonitorStatusPublisher(dns.RuntimeStatus, monitorPath,()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,()=>dns.RequestProcessor.Bindings.Read(),activeProducer is null?null:()=>activeProducer.Health);
    var monitoring = monitor?.RunAsync(shutdown.Token) ?? Task.CompletedTask;
    var bindingRefresh=Task.Run(()=>activeProducer is null?bindingProducer.RunAsync(shutdown.Token):activeEnabled?activeProducer.RunAsync(shutdown.Token):Task.WhenAll(bindingProducer.RunAsync(shutdown.Token),activeProducer.RunAsync(shutdown.Token)));
    try { return await new EngineLifetime(api, dns).RunAsync(shutdown.Token); }
    finally { shutdown.Cancel(); await monitoring; await bindingRefresh; }
}
catch (Exception)
{
    EngineLog.Failure("Engine", "Configuration or component initialization failed");
    return 1;
}
finally { Console.CancelKeyPress -= cancelHandler; }

static int ReadIntegerEnvironment(string name, int defaultValue)
{
    var value = Environment.GetEnvironmentVariable(name);
    if (value == null) return defaultValue;
    if (!int.TryParse(value, System.Globalization.NumberStyles.None,
        System.Globalization.CultureInfo.InvariantCulture, out var parsed))
        throw new InvalidOperationException("Invalid numeric Engine configuration");
    return parsed;
}
