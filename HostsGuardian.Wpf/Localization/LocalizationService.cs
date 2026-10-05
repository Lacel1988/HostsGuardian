using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Windows.Data;
using System.Windows.Markup;
using HostsGuardian.Wpf.Services;

namespace HostsGuardian.Wpf.Localization;

/// <summary>One resource catalog for views, dialogs, events and notifications.</summary>
public sealed class LocalizationService : INotifyPropertyChanged
{
    public static LocalizationService Instance { get; } = new();
    public static IReadOnlyDictionary<string, string> English { get; } = Load("en");
    public static IReadOnlyDictionary<string, string> Hungarian { get; } = Load("hu");
    private static readonly Dictionary<string, string> SourceKeys = English.GroupBy(p => p.Value, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Key, StringComparer.Ordinal);
    private static readonly Dictionary<string, string> HungarianSourceKeys = Hungarian.GroupBy(p => p.Value, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Key, StringComparer.Ordinal);
    private string _language = "en";
    public string Language => _language;
    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? LanguageChanged;
    private static Dictionary<string, string> Load(string language)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"HostsGuardian.Wpf.Localization.{language}.json")
            ?? throw new InvalidOperationException("Localization resource missing");
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
    }
    public string this[string key] => (_language == "hu" ? Hungarian : English).GetValueOrDefault(key)
        ?? English.GetValueOrDefault(key) ?? key;
    public void ChangeLanguage(string language, bool persist = true)
    {
        if (language is not ("en" or "hu")) language = "en";
        if (persist) UiPreferences.Current.SaveLanguage(language); // Keep current UI if persistence fails.
        if (_language == language) return;
        _language = language;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
    private static readonly IReadOnlyDictionary<string, string> MachineKeys = new Dictionary<string, string>
    { ["GlobalBlock"] = "Reason.GlobalBlock", ["GlobalAllow"] = "Reason.GlobalAllow", ["DeviceOverride"] = "Reason.DeviceOverride",
      ["SafeModeBypass"] = "Reason.SafeMode", ["FilteringDisabled"] = "Reason.Disabled" };
    public static string T(string source) => Instance[MachineKeys.GetValueOrDefault(source) ?? SourceKeys.GetValueOrDefault(source) ?? HungarianSourceKeys.GetValueOrDefault(source) ?? source];
    public static string Display(string text)
    {
        if (SourceKeys.ContainsKey(text) || HungarianSourceKeys.ContainsKey(text)) return T(text);
        // Relocalize an existing error heading without altering opaque diagnostic payloads.
        foreach (var source in English.Values.Concat(Hungarian.Values).Where(v => !v.Contains('{')).OrderByDescending(v => v.Length))
        {
            var prefix = source.EndsWith(": ", StringComparison.Ordinal) ? source : source + ": ";
            if (text.StartsWith(prefix, StringComparison.Ordinal)) return T(source) + (source.EndsWith(": ", StringComparison.Ordinal) ? "" : ": ") + T(text[prefix.Length..]);
        }
        return text;
    }
    public static string F(string source, params object?[] args)
    {
        try { return string.Format(CultureInfo.GetCultureInfo(Instance.Language), T(source), args); }
        catch (FormatException)
        {
            try { return string.Format(CultureInfo.InvariantCulture, source, args); }
            catch (FormatException) { return T(source); }
        }
    }
}

[MarkupExtensionReturnType(typeof(string))]
public sealed class TextExtension : MarkupExtension
{
    public TextExtension() { }
    public TextExtension(string key) => Key = key;
    public string Key { get; set; } = "";
    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]") { Source = LocalizationService.Instance, Mode = BindingMode.OneWay }.ProvideValue(serviceProvider);
}
