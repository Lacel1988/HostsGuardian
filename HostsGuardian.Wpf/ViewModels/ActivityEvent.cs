using System.Text.Json;
using HostsGuardian.Core.Services;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

namespace HostsGuardian.Wpf.ViewModels;

/// <summary>Optional identity/target metadata; null actor means no authenticated WPF identity exists.</summary>
public sealed record ActivityEvent(string Source, string Category, string Template, string[] Arguments,
    string? Actor = null, string? Target = null, string? PreviousAction = null, string? Action = null, string? Outcome = null)
{
    public const string Prefix = "HG-WPF-EVENT ";
    public string Serialize() => Prefix + JsonSerializer.Serialize(this with
    { Arguments = Arguments.Select(SecretRedactor.Clean).ToArray(), Actor = Actor == null ? null : SecretRedactor.Clean(Actor) });
    public string Display => L.F(Template, Arguments.Select(a => a == PreviousAction || a == Action ? L.T(a) : a).Cast<object?>().ToArray());
    public static ActivityEvent? Parse(string message)
    {
        if (!message.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        try
        {
            var entry = JsonSerializer.Deserialize<ActivityEvent>(message[Prefix.Length..]);
            return entry?.Template != null && entry.Arguments != null && entry.Arguments.All(a => a != null) ? entry : null;
        }
        catch (JsonException) { return null; }
    }
}
