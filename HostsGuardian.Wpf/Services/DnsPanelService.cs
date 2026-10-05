using L = HostsGuardian.Wpf.Localization.LocalizationService;
using System;
using System.Diagnostics;
using System.Text;

namespace HostsGuardian.Wpf.Services
{
    public sealed class DnsPanelService
    {
        public string GetSnapshot()
        {
            try
            {
                // netsh -> DNS szerverek listája (info-only)
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip show dns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var p = Process.Start(psi);
                var output = p?.StandardOutput.ReadToEnd() ?? "";
                var err = p?.StandardError.ReadToEnd() ?? "";
                p?.WaitForExit(4000);

                var sb = new StringBuilder();
                sb.AppendLine(L.T("DNS status (info-only)"));
                sb.AppendLine("----------------------");
                if (!string.IsNullOrWhiteSpace(output)) sb.AppendLine(output.Trim());
                if (!string.IsNullOrWhiteSpace(err)) sb.AppendLine(L.T("WARN: ") + err.Trim());

                return sb.ToString().Trim();
            }
            catch (Exception ex)
            {
                return L.T("DNS status: error: ") + ex.Message;
            }
        }
    }
}
