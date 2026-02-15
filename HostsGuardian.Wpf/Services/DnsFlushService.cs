using System;
using System.Diagnostics;

namespace HostsGuardian.Wpf.Services
{
    public sealed class DnsFlushService
    {
        public bool TryFlush(out string message)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var p = Process.Start(psi);
                if (p == null)
                {
                    message = "DNS flush failed: process could not start.";
                    return false;
                }

                var stdout = p.StandardOutput.ReadToEnd();
                var stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();

                if (p.ExitCode == 0)
                {
                    message = string.IsNullOrWhiteSpace(stdout) ? "DNS flushed." : stdout.Trim();
                    return true;
                }

                message = ("DNS flush failed. " + stderr).Trim();
                return false;
            }
            catch (Exception ex)
            {
                message = "DNS flush error: " + ex.Message;
                return false;
            }
        }
    }
}
