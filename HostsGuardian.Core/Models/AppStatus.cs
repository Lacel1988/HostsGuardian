using System;

namespace HostsGuardian.Core.Models
{
    public sealed class AppStatus
    {
        public bool HostsBlockActive { get; set; }
        public int BlockedDomainCount { get; set; }
        public string? LastAppliedBy { get; set; }
        public DateTime? LastAppliedAtUtc { get; set; }
    }
}
