using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services
{
    public sealed class StatusExportService
    {
        // AppStatus export (Console "status" parancshoz)
        public string Export(AppStatus status)
        {
            Directory.CreateDirectory(PathsService.AppFolder);

            var json = JsonSerializer.Serialize(status, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(PathsService.StatusPath, json, Encoding.UTF8);
            return PathsService.StatusPath;
        }

        // Activity export (WPF Activity panel export gombokhoz)
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
                sb.Append(EscapeCsv(e.Message));
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public string ExportActivityJson(IEnumerable<AuditLogEntry> entries)
        {
            var data = entries ?? Enumerable.Empty<AuditLogEntry>();
            return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
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
