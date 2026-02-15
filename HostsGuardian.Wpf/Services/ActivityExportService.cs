using System;
using System.Collections.Generic;
using System.IO;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;

namespace HostsGuardian.Wpf.Services
{
    public sealed class ActivityExportService
    {
        private readonly FileDialogService _dialog;
        private readonly StatusExportService _exporter;

        public ActivityExportService(FileDialogService dialog, StatusExportService exporter)
        {
            _dialog = dialog;
            _exporter = exporter;
        }

        public bool ExportCsv(string suggestedName, out string message, Func<IEnumerable<AuditLogEntry>> getEntries)
        {
            var path = _dialog.SaveFile(
                filter: "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                defaultExt: ".csv",
                defaultFileName: suggestedName
            );

            if (path == null)
            {
                message = "Export cancelled.";
                return false;
            }

            try
            {
                var csv = _exporter.ExportActivityCsv(getEntries());
                File.WriteAllText(path, csv);
                message = "CSV exported: " + path;
                return true;
            }
            catch (Exception ex)
            {
                message = "Export failed: " + ex.Message;
                return false;
            }
        }

        public bool ExportJson(string suggestedName, out string message, Func<IEnumerable<AuditLogEntry>> getEntries)
        {
            var path = _dialog.SaveFile(
                filter: "JSON files (*.json)|*.json|All files (*.*)|*.*",
                defaultExt: ".json",
                defaultFileName: suggestedName
            );

            if (path == null)
            {
                message = "Export cancelled.";
                return false;
            }

            try
            {
                var json = _exporter.ExportActivityJson(getEntries());
                File.WriteAllText(path, json);
                message = "JSON exported: " + path;
                return true;
            }
            catch (Exception ex)
            {
                message = "Export failed: " + ex.Message;
                return false;
            }
        }
    }
}
