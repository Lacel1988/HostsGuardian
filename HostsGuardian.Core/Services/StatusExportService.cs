using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services
{
    public sealed class StatusExportService
    {
        public string ExportActivityCsv(IEnumerable<AuditLogEntry> entries)
        {
            var sb = new StringBuilder();
            sb.AppendLine("AtUtc,Level,Message");

            foreach (var e in entries ?? Enumerable.Empty<AuditLogEntry>())
            {
                sb.Append(EscapeCsv(e.AtUtc.ToString("o")));
                sb.Append(',');
                sb.Append(EscapeCsv(e.Level));
                sb.Append(',');
                sb.Append(EscapeCsv(SecretRedactor.Clean(e.Message)));
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public string ExportActivityJson(IEnumerable<AuditLogEntry> entries)
        {
            var data = entries ?? Enumerable.Empty<AuditLogEntry>();
            return SecretRedactor.Clean(JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
        }

        private static string EscapeCsv(string? s)
        {
            s ??= "";
            var mustQuote = s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r');
            if (!mustQuote) return s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }
    }
}
