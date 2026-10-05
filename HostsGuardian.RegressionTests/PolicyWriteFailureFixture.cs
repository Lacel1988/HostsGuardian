/// <summary>Induces an actual storage failure using native filesystem semantics.</summary>
internal sealed class PolicyWriteFailureFixture : IDisposable
{
    private readonly FileStream? _locked;
    private readonly string? _directory;
    private readonly UnixFileMode _originalMode;

    public PolicyWriteFailureFixture(string policyPath)
    {
        if (!File.Exists(policyPath)) throw new ArgumentException("Fixture policy must already exist");
        if (OperatingSystem.IsWindows())
            _locked = new FileStream(policyPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        else
        {
            _directory = Path.GetDirectoryName(Path.GetFullPath(policyPath))!;
            _originalMode = File.GetUnixFileMode(_directory);
            File.SetUnixFileMode(_directory, _originalMode &
                ~(UnixFileMode.UserWrite | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite));
        }
    }

    public void Dispose()
    {
        _locked?.Dispose();
        if (!OperatingSystem.IsWindows() && _directory != null)
            File.SetUnixFileMode(_directory, _originalMode);
    }
}
