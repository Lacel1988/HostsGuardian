using System;
using System.Collections.Generic;
using HostsGuardian.Core.Services;

namespace HostsGuardian.Wpf.Services
{
    public sealed class DnsProxyHostService
    {
        private readonly DnsProxyService _dns = new();

        public bool IsRunning => _dns.IsRunning;
        public int Port => _dns.ListenPort;

        public event Action<DnsProxyService.DnsLogItem>? OnLog
        {
            add { _dns.OnLog += value; }
            remove { _dns.OnLog -= value; }
        }

        public void Configure(List<string> globalBlocked, Dictionary<string, List<string>> perClientIp)
        {
            _dns.BlockedDomains = globalBlocked ?? new List<string>();
            _dns.BlockedByClientIp = perClientIp ?? new Dictionary<string, List<string>>();
        }

        public void Start(int port)
        {
            _dns.Start(port);
        }

        public void Stop()
        {
            _dns.Stop();
        }
    }
}
