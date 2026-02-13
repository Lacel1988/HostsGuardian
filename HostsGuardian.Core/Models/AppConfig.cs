using System;
using System.Collections.Generic;

namespace HostsGuardian.Core.Models;

public sealed class AppConfig
{
    public List<DomainEntry> BlockedDomains { get; set; } = new();

    public string? LastAppliedBy { get; set; }
    public DateTime? LastAppliedAtUtc { get; set; }
}
