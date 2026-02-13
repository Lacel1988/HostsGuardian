namespace HostsGuardian.Wpf.Services
{
    public interface IFileDialogService
    {
        // returns full path or null if canceled
        string? SaveFile(string title, string filter, string defaultFileName);
    }
}
