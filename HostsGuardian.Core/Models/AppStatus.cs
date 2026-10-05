using System;

namespace HostsGuardian.Core.Models
{
    public sealed class AppStatus
    {
        public int BlockedDomainCount { get; set; }
        public string? LastAppliedBy { get; set; }
        public DateTime? LastAppliedAtUtc { get; set; }
    }
}
