internal static class SourceLayout
{
    static DirectoryInfo Find(Func<string, bool> accepts, string scope)
    {
        for (var root = new DirectoryInfo(AppContext.BaseDirectory); root != null; root = root.Parent)
            if (accepts(root.FullName)) return root;
        throw new InvalidOperationException($"{scope} source root not found; run from the complete repository checkout");
    }
    public static DirectoryInfo EngineRoot() => Find(p => File.Exists(Path.Combine(p, "HostsGuardian.DnsEngine", "HostsGuardian.DnsEngine.csproj")), "RC.2 Engine");
    public static DirectoryInfo LegacyWpfRoot() => Find(p => File.Exists(Path.Combine(p, "HostsGuardian.Wpf", "ViewModels", "MainViewModel.cs")), "Historical WPF");
}
