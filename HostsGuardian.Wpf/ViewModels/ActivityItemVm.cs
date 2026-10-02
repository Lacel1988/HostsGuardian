using System;

namespace HostsGuardian.Wpf.ViewModels
{
    public class ActivityItemVm
    {
        public ActivityItemVm() { } // fontos: legyen default ctor

        public ActivityItemVm(DateTime atUtc, string level, string message)
        {
            AtUtc = atUtc;
            Level = level ?? "";
            Message = message ?? "";
        }

        public DateTime AtUtc { get; set; } = DateTime.UtcNow;
        public string Level { get; set; } = "INFO";
        public string Message { get; set; } = "";

        public string Header => $"{AtUtc:yyyy-MM-dd HH:mm:ss}  [{Level}]";

        public string Time => AtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    }
}
