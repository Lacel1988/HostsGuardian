using System;

namespace HostsGuardian.Core.Models
{
    public sealed class AuditLogEntry
    {
        public DateTime AtUtc { get; set; }
        public string Level { get; set; } = "INFO";
        public string Message { get; set; } = "";
    }
}
