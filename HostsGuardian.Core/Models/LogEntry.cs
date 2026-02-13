using System;

namespace HostsGuardian.Core.Models
{
    public class LogEntry
    {
        public DateTime AtUtc { get; set; }
        public string Action { get; set; } = "";
        public string Message { get; set; } = "";
    }
}
