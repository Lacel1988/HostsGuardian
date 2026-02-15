using System;
using System.IO;

namespace HostsGuardian.Core.Services
{
    public static class PathsService
    {
        public static string AppFolder
        {
            get
            {
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(root, "HostsGuardian");
            }
        }

        public static string ConfigPath => Path.Combine(AppFolder, "config.json");
        public static string AuditLogPath => Path.Combine(AppFolder, "audit.log");
        public static string StatusPath => Path.Combine(AppFolder, "status.json");

        public static string HostsDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers",
            "etc"
        );

        public static string HostsPath => Path.Combine(HostsDir, "hosts");
    }
}
