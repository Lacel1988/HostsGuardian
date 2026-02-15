using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services
{
    public sealed class AuditLogService
    {
        private readonly object _lock = new();

        public void Write(string message, string level = "INFO")
        {
            var entry = new AuditLogEntry
            {
                AtUtc = DateTime.UtcNow,
                Level = string.IsNullOrWhiteSpace(level) ? "INFO" : level.Trim().ToUpperInvariant(),
                Message = message ?? ""
            };

            var line = Serialize(entry);

            lock (_lock)
            {
                Directory.CreateDirectory(PathsService.AppFolder);
                File.AppendAllText(PathsService.AuditLogPath, line + Environment.NewLine);
            }
        }

        public List<AuditLogEntry> ReadLast(int max = 100)
        {
            if (max <= 0) return new List<AuditLogEntry>();
            if (!File.Exists(PathsService.AuditLogPath)) return new List<AuditLogEntry>();

            var lines = File.ReadAllLines(PathsService.AuditLogPath);
            return lines
                .Reverse()
                .Take(max)
                .Reverse()
                .Select(TryParse)
                .Where(x => x != null)
                .Cast<AuditLogEntry>()
                .ToList();
        }

        private static string Serialize(AuditLogEntry e)
        {
            var ts = e.AtUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
            return $"{ts} | {e.Level} | {e.Message}";
        }

        private static AuditLogEntry? TryParse(string line)
        {
            try
            {
                var parts = line.Split(new[] { " | " }, 3, StringSplitOptions.None);
                if (parts.Length != 3) return null;

                if (!DateTime.TryParse(parts[0], CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var dt))
                    return null;

                return new AuditLogEntry
                {
                    AtUtc = dt,
                    Level = parts[1],
                    Message = parts[2]
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
