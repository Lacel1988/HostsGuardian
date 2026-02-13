namespace HostsGuardian.Wpf.Services;

public interface IDialogService
{
    void Info(string message, string title = "Info");
    void Error(string message, string title = "Error");
}
