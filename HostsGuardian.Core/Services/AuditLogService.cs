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
        private readonly string _path;
        public AuditLogService(string? path = null) => _path = path ?? PathsService.AuditLogPath;

        public void Write(string message, string level = "INFO")
        {
            var entry = new AuditLogEntry
            {
                AtUtc = DateTime.UtcNow,
                Level = string.IsNullOrWhiteSpace(level) ? "INFO" : level.Trim().ToUpperInvariant(),
                Message = SecretRedactor.Clean(message)
            };

            var line = Serialize(entry);

            lock (_lock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
                File.AppendAllText(_path, line + Environment.NewLine);
            }
        }

        public List<AuditLogEntry> ReadLast(int max = 100)
        {
            if (max <= 0) return new List<AuditLogEntry>();
            if (!File.Exists(_path)) return new List<AuditLogEntry>();

            var lines = File.ReadAllLines(_path);
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
                    Message = SecretRedactor.Clean(parts[2])
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
