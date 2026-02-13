using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using HostsGuardian.Wpf.ViewModels;

namespace HostsGuardian.Wpf.Services
{
    public class ActivityExportService
    {
        public string BuildCsv(IEnumerable<ActivityItemVm> items)
        {
            var sb = new StringBuilder();
            sb.AppendLine("atUtc,level,message");

            foreach (var it in items ?? Enumerable.Empty<ActivityItemVm>())
            {
                var at = it.AtUtc.ToString("o");
                var lvl = EscapeCsv(it.Level);
                var msg = EscapeCsv(it.Message);
                sb.AppendLine($"{at},{lvl},{msg}");
            }

            return sb.ToString();
        }

        public string BuildJson(IEnumerable<ActivityItemVm> items)
        {
            // Minimal JSON (külön lib nélkül)
            var list = (items ?? Enumerable.Empty<ActivityItemVm>())
                .Select(i => new
                {
                    atUtc = i.AtUtc.ToString("o"),
                    level = i.Level ?? "",
                    message = i.Message ?? ""
                })
                .ToList();

            return SimpleJson.Serialize(list);
        }

        private static string EscapeCsv(string? s)
        {
            s ??= "";
            var mustQuote = s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r');
            s = s.Replace("\"", "\"\"");
            return mustQuote ? $"\"{s}\"" : s;
        }

        private static class SimpleJson
        {
            public static string Serialize(object obj)
            {
                // nagyon egyszerű, listához elég
                if (obj is IEnumerable<object> enumerable)
                {
                    var parts = enumerable.Select(SerializeObject);
                    return "[" + string.Join(",", parts) + "]";
                }
                return SerializeObject(obj);
            }

            private static string SerializeObject(object o)
            {
                var props = o.GetType().GetProperties();
                var parts = new List<string>();
                foreach (var p in props)
                {
                    var name = p.Name;
                    var val = p.GetValue(o);
                    parts.Add($"\"{Escape(name)}\":{SerializeValue(val)}");
                }
                return "{" + string.Join(",", parts) + "}";
            }

            private static string SerializeValue(object? v)
            {
                if (v == null) return "null";
                if (v is string s) return $"\"{Escape(s)}\"";
                return $"\"{Escape(v.ToString() ?? "")}\"";
            }

            private static string Escape(string s)
                => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n");
        }
    }
}
