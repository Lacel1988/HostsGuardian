using Microsoft.Win32;

namespace HostsGuardian.Wpf.Services
{
    public sealed class FileDialogService
    {
        public string? SaveFile(string filter, string defaultExt, string defaultFileName)
        {
            var dlg = new SaveFileDialog
            {
                Filter = filter,
                DefaultExt = defaultExt,
                FileName = defaultFileName,
                AddExtension = true,
                OverwritePrompt = true
            };

            var ok = dlg.ShowDialog();
            return ok == true ? dlg.FileName : null;
        }
    }
}
