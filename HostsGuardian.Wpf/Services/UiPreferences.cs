using System.IO;
using System.Text.Json;

namespace HostsGuardian.Wpf.Services;

public enum NotificationCategory { EngineDns, Policy, NewDevices, Recovery }
public sealed record UiPreferenceData(string Language = "en", bool EngineDns = true, bool Policy = true,
    bool NewDevices = true, bool Recovery = true);

/// <summary>UI-only settings, deliberately separate from policy, credentials and trust.</summary>
public sealed class UiPreferences
{
    public static UiPreferences Current { get; private set; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HostsGuardian", "ui-preferences.json"));
    private readonly string _path;
    public UiPreferenceData Data { get; private set; } = new();
    public bool LoadFailed { get; private set; }
    public UiPreferences(string path)
    {
        _path = path;
        try { if (File.Exists(path)) Data = JsonSerializer.Deserialize<UiPreferenceData>(File.ReadAllText(path)) ?? new(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { LoadFailed = true; }
    }
    public static void Use(UiPreferences preferences) => Current = preferences;
    public bool Enabled(NotificationCategory category) => category switch
    { NotificationCategory.EngineDns => Data.EngineDns, NotificationCategory.Policy => Data.Policy,
      NotificationCategory.NewDevices => Data.NewDevices, _ => Data.Recovery };
    public void SaveLanguage(string language) => Save(Data with { Language = language });
    public void SetEnabled(NotificationCategory category, bool enabled) => Save(category switch
    { NotificationCategory.EngineDns => Data with { EngineDns = enabled }, NotificationCategory.Policy => Data with { Policy = enabled },
      NotificationCategory.NewDevices => Data with { NewDevices = enabled }, _ => Data with { Recovery = enabled } });
    private void Save(UiPreferenceData data)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temporary, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true })); File.Move(temporary, _path, true); Data = data; LoadFailed = false; }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
