using System.Windows;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Services;
using HostsGuardian.Wpf.ViewModels;

namespace HostsGuardian.Wpf
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            var configSvc = new ConfigService();
            var hostsSvc = new HostsService();
            var auditSvc = new AuditLogService();
            var statusExportSvc = new StatusExportService();

            var fileDlg = new FileDialogService(); // ezt te már használod

            DataContext = new MainViewModel(configSvc, hostsSvc, auditSvc, statusExportSvc, fileDlg);
        }
    }
}
