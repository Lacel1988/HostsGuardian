using Microsoft.Win32;

namespace HostsGuardian.Wpf.Services
{
    public sealed class FileDialogService : IFileDialogService
    {
        public string? SaveFile(string title, string filter, string defaultFileName)
        {
            var dlg = new SaveFileDialog
            {
                Title = title,
                Filter = filter,
                FileName = defaultFileName,
                AddExtension = true,
                OverwritePrompt = true
            };

            var ok = dlg.ShowDialog();
            return ok == true ? dlg.FileName : null;
        }
    }
}
