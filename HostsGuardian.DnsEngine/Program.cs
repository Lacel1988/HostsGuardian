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
    // Scope approval must use restored registrations, not the pre-start empty snapshot.
    api.InitializePolicyForStartup();
    var monitorPath = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_MONITOR_STATUS_FILE");
    var evidenceAge=ValidatedBindingProducer.ParseEvidenceAge(Environment.GetEnvironmentVariable("HOSTSGUARDIAN_BINDING_MAX_AGE_SECONDS"));
    if(evidenceAge==TimeSpan.Zero)EngineLog.Failure("Binding","Invalid freshness setting; passive bindings disabled; DNS remains available");
    var bindingProducer=new ValidatedBindingProducer(dns.RequestProcessor.Bindings,
        ()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,
        HostsGuardian.Core.Services.PassiveIdentityEvidence.ReadBindingEvidence,maximumEvidenceAge:evidenceAge);
    var validatorSocket=Environment.GetEnvironmentVariable("HOSTSGUARDIAN_VALIDATOR_SOCKET");
    var activeScope=ActiveValidationScope.Parse(Environment.GetEnvironmentVariable("HOSTSGUARDIAN_ACTIVE_VALIDATION"),
        Environment.GetEnvironmentVariable("HOSTSGUARDIAN_ACTIVE_VALIDATION_DEVICE_IDS"),
        Environment.GetEnvironmentVariable("HOSTSGUARDIAN_ACTIVE_VALIDATION_SECONDS"),
        dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty);
    var validatorClient=string.IsNullOrEmpty(validatorSocket)?null:new NetworkValidatorClient(validatorSocket);
    var passiveL2Enabled=Environment.GetEnvironmentVariable("HOSTSGUARDIAN_PASSIVE_DNS_L2")=="1";
    var passiveL2=validatorClient is null?null:new PassiveDnsL2BindingProducer(dns.RequestProcessor.Bindings,
        ()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,
        HostsGuardian.Core.Services.PassiveIdentityEvidence.ReadBindingEvidence,validatorClient,maximumEvidenceAge:evidenceAge);
    if(passiveL2Enabled && passiveL2 is null)EngineLog.Failure("Binding","Passive L2 requested without trusted validator; bindings disabled");
    if (passiveL2Enabled && passiveL2 is not null)
        dns.RequestProcessor.BindingRefresh = new RequestBindingRefresh(passiveL2.RefreshAsync,context=>
            AddressBindingStore.Resolve(dns.RequestProcessor.Bindings.ReadFor(context),
                dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,
                context,DateTimeOffset.UtcNow).DeviceId is not null);
    var activeProducer=string.IsNullOrEmpty(validatorSocket)?null:new ActiveBindingProducer(dns.RequestProcessor.Bindings,
        ()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,
        HostsGuardian.Core.Services.PassiveIdentityEvidence.ReadBindingEvidence,validatorClient!,activeValidationEnabled:true,
        scope:activeScope,passiveFallback:passiveL2Enabled?()=>dns.RequestProcessor.Bindings.PublishObserved([]):bindingProducer.Refresh,
        passiveRefresh:passiveL2Enabled?passiveL2!.RefreshAsync:null);
    var monitor = monitorPath == null ? null : new LocalMonitorStatusPublisher(dns.RuntimeStatus, monitorPath,()=>dns.PolicyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty,()=>dns.RequestProcessor.Bindings.Read(),activeProducer is null?null:()=>activeProducer.Health with{PassiveDnsL2State=passiveL2Enabled?passiveL2!.State:"Disabled",PassiveDnsL2Reason=passiveL2Enabled?passiveL2!.Reason:"Receive-only evidence not enabled",CaptureInstance=passiveL2Enabled?passiveL2!.CaptureInstance:null,InterfaceGeneration=passiveL2Enabled?passiveL2!.InterfaceGeneration:0});
    var monitoring = monitor?.RunAsync(shutdown.Token) ?? Task.CompletedTask;
    var bindingRefresh=Task.Run(()=>activeProducer is null?(passiveL2Enabled?Task.CompletedTask:bindingProducer.RunAsync(shutdown.Token)):activeProducer.RunAsync(shutdown.Token));
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
