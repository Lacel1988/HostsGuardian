using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class ArchitectureTests
{
    public static void Run(Action<string, Action> test)
    {
        static void Check(bool value, string message) { if (!value) throw new Exception(message); }
        test("custom Engine production ports and read-only transport status", () =>
        {
            var config = new EngineConfig();
            Check(config.DnsListenPort == 53 && config.ApiPort == 3000, "Production ports changed");
            var rules = new RuleStore("architecture-fixture");
            rules.SetBlockedDomains(new[] { "explicit.invalid" });
            var dns = new DnsProxyServer(rules, config);
            var api = new ApiServer(rules, config, dns);
            var status = api.GetDnsStatus();
            Check(status.Implementation == "HostsGuardian.DnsEngine" && status.DnsPort == 53 && status.ApiPort == 3000, "Wrong implementation/ports");
            Check(!status.UdpListening && !status.TcpListening && status.TcpImplemented && status.TcpTargetPort == 53, "Unstarted transport falsely active");
            Check(rules.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }), "Status changed policy");
        });
        test("competing executors and lease-reader types are absent", () =>
        {
            var types = typeof(DnsEngineService).Assembly.GetTypes().Concat(typeof(ApiServer).Assembly.GetTypes()).Select(t => t.Name).ToArray();
            Check(!types.Any(t => t is "DnsProxyService" or "DnsProxyHostService" or "DnsmasqApplyService" or "DhcpLeaseReader"), "Competing architecture remains compiled");
        });
        test("production Engine source cannot orchestrate external DNS services", () =>
        {
            var root = new DirectoryInfo(AppContext.BaseDirectory);
            while (root != null && !File.Exists(Path.Combine(root.FullName, "HostsGuardian.sln"))) root = root.Parent;
            Check(root != null, "Source root not found");
            var files = Directory.EnumerateFiles(Path.Combine(root!.FullName, "HostsGuardian.DnsEngine"), "*.cs", SearchOption.AllDirectories)
                .Where(p => !p.Split(Path.DirectorySeparatorChar).Any(part => part is "obj" or "bin"));
            var source = string.Join("\n", files.Select(File.ReadAllText));
            foreach (var forbidden in new[] { "dnsmasq", "systemctl", "Process.Start", "/dns/apply", "/dns/revert", "DhcpLeaseReader" })
                Check(!source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "External filtering path: " + forbidden);
        });
    }
}
