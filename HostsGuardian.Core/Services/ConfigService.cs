using System.IO;
using System.Text.Json;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public sealed class ConfigService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true
    };

    public AppConfig Load()
    {
        try
        {
            Directory.CreateDirectory(PathsService.AppFolder); // +++

            if (!File.Exists(PathsService.ConfigPath))
                return new AppConfig();

            var json = File.ReadAllText(PathsService.ConfigPath);
            var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts);
            return cfg ?? new AppConfig();
        }
        catch
        {
            return new AppConfig();
        }
    }

    public void Save(AppConfig cfg)
    {
        Directory.CreateDirectory(PathsService.AppFolder); // +++

        var json = JsonSerializer.Serialize(cfg, JsonOpts);
        File.WriteAllText(PathsService.ConfigPath, json);
    }
}
