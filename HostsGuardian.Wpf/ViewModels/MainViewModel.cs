using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Services;

namespace HostsGuardian.Wpf.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly ConfigService _configSvc;
        private readonly HostsService _hostsSvc;
        private readonly AuditLogService _auditSvc;
        private readonly StatusExportService _statusExportSvc;
        private readonly IFileDialogService _fileDlg;

        private AppConfig _cfg = new();

        public MainViewModel(
            ConfigService configSvc,
            HostsService hostsSvc,
            AuditLogService auditSvc,
            StatusExportService statusExportSvc,
            IFileDialogService fileDlg)
        {
            _configSvc = configSvc;
            _hostsSvc = hostsSvc;
            _auditSvc = auditSvc;
            _statusExportSvc = statusExportSvc;
            _fileDlg = fileDlg;

            Refresh();
        }

        [ObservableProperty] private string _search = "";
        [ObservableProperty] private string _newDomain = "";
        [ObservableProperty] private DomainEntry? _selectedDomain;

        [ObservableProperty] private string _previewText = "";

        public IEnumerable<DomainEntry> FilteredDomains =>
            (_cfg.BlockedDomains ?? new List<DomainEntry>())
                .Where(d =>
                    string.IsNullOrWhiteSpace(Search) ||
                    (d.Domain?.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase) ?? false))
                .OrderBy(d => d.Domain, StringComparer.OrdinalIgnoreCase);

        public ObservableCollection<ActivityItemVm> ActivityItems { get; } = new();

        partial void OnSearchChanged(string value) => OnPropertyChanged(nameof(FilteredDomains));

        [RelayCommand]
        private void Refresh()
        {
            _cfg = _configSvc.Load();
            OnPropertyChanged(nameof(FilteredDomains));

            PreviewText = "";
            LoadActivityPanel();
        }

        [RelayCommand]
        private void AddDomain()
        {
            var raw = NewDomain ?? "";
            var dom = HostsService.NormalizeDomain(raw);

            if (string.IsNullOrWhiteSpace(dom) || !dom.Contains('.'))
                return;

            _cfg.BlockedDomains ??= new List<DomainEntry>();

            if (_cfg.BlockedDomains.Any(x => string.Equals(x.Domain, dom, StringComparison.OrdinalIgnoreCase)))
                return;

            _cfg.BlockedDomains.Add(new DomainEntry { Domain = dom });
            _configSvc.Save(_cfg);

            _auditSvc.Write($"Added domain: {dom}", "INFO");

            NewDomain = "";
            OnPropertyChanged(nameof(FilteredDomains));
            LoadActivityPanel();
        }

        [RelayCommand]
        private void RemoveDomain()
        {
            if (SelectedDomain == null) return;

            _cfg.BlockedDomains ??= new List<DomainEntry>();
            _cfg.BlockedDomains.RemoveAll(x =>
                string.Equals(x.Domain, SelectedDomain.Domain, StringComparison.OrdinalIgnoreCase));

            _configSvc.Save(_cfg);

            _auditSvc.Write($"Removed domain: {SelectedDomain.Domain}", "INFO");

            SelectedDomain = null;
            OnPropertyChanged(nameof(FilteredDomains));
            LoadActivityPanel();
        }

        [RelayCommand]
        private void Preview()
        {
            PreviewText = _hostsSvc.PreviewResult(_cfg);
            _auditSvc.Write($"Preview generated. Domains: {_cfg.BlockedDomains?.Count ?? 0}", "INFO");
            LoadActivityPanel();
        }

        [RelayCommand]
        private void Apply()
        {
            _hostsSvc.Apply(_cfg);

            _cfg.LastAppliedBy = AdminService.CurrentUser();
            _cfg.LastAppliedAtUtc = DateTime.UtcNow;
            _configSvc.Save(_cfg);

            _auditSvc.Write($"Applied hosts block. Domains: {_cfg.BlockedDomains?.Count ?? 0}", "INFO");
            LoadActivityPanel();
        }

        [RelayCommand]
        private void Revert()
        {
            _hostsSvc.Revert();
            _auditSvc.Write("Reverted HostsGuardian block.", "WARN");
            LoadActivityPanel();
        }

        [RelayCommand]
        private void ExportCsv()
        {
            var path = _fileDlg.SaveFile(
                "Export activity (CSV)",
                $"hosts-guardian-activity-{DateTime.Now:yyyyMMdd-HHmm}.csv",
                "CSV (*.csv)|*.csv|All files (*.*)|*.*");

            if (string.IsNullOrWhiteSpace(path))
                return;

            var entries = _auditSvc.ReadLast(100);
            var csv = _statusExportSvc.ExportActivityCsv(entries);

            File.WriteAllText(path, csv);
            _auditSvc.Write($"Exported activity CSV: {path}", "INFO");
            LoadActivityPanel();
        }

        [RelayCommand]
        private void ExportJson()
        {
            var path = _fileDlg.SaveFile(
                "Export activity (JSON)",
                $"hosts-guardian-activity-{DateTime.Now:yyyyMMdd-HHmm}.json",
                "JSON (*.json)|*.json|All files (*.*)|*.*");

            if (string.IsNullOrWhiteSpace(path))
                return;

            var entries = _auditSvc.ReadLast(100);
            var json = _statusExportSvc.ExportActivityJson(entries);

            File.WriteAllText(path, json);
            _auditSvc.Write($"Exported activity JSON: {path}", "INFO");
            LoadActivityPanel();
        }

        private void LoadActivityPanel()
        {
            ActivityItems.Clear();

            var entries = _auditSvc.ReadLast(100);
            foreach (var e in entries)
            {
                ActivityItems.Add(new ActivityItemVm(e.AtUtc, e.Level, e.Message));
            }
        }
    }
}
