# Phase 1–2 review boundary

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

The local working tree is primary. No remote synchronization or commit was performed.
Checkpoint: a private, local `HostsGuardian-pre-codex-20261002-083645` snapshot outside the public repository. Its location is retained in local recovery records.
Its `tree` contains the full original directory including .git, .vs, ignored build files,
and untracked Engine files. `manifest.json` records SHA-256 for 2,475 files.

## Restore (only when explicitly requested)

Close HostsGuardian and Visual Studio. Rename the current project directory to preserve
subsequent work, then copy checkpoint `tree` to the original project path. Do not copy
over the current directory: extra files would survive and the result would not match the checkpoint.
Verify restored file hashes against the manifest. The snapshot does not include external
Windows hosts/configuration files because source work does not modify those files.

## Behavior

- New or legacy entries without mechanism flags are unchecked. Review legacy entries and
  select HOSTS and/or DNS explicitly. Editing checkboxes saves desired policy only.
- Apply Hosts uses only HOSTS-selected entries. Push DNS replaces Engine policy with only
  DNS-selected entries. Removing/unchecking entries takes effect on the next explicit Apply/Push.
- Local hosts emits IPv4 plus IPv6 mappings for the selected exact name and its www alias
  (unless the selected name already begins with www). Hosts has no wildcard support.
- DNS matching retains selected-name plus descendant semantics. Only selected names are
  stored; removing a parent does not leave a generated www rule.
- Normalization preserves selected subdomains, canonicalizes IDN and trailing dots, and
  rejects invalid names. It never converts a selected www name into its parent.
- Both current and legacy owned hosts blocks are recognized. Unrelated text survives;
  malformed markers refuse changes. Backups precede successful writes. Preview is read-only.
- Device policy saves normalized observed MAC and current IP; legacy IP-only entries remain
  unassigned. Rows without observed MAC are not persisted as new identity policies.
- Reverse DNS metadata lookup has a 250 ms deadline per host.

## Verification

Run `dotnet build HostsGuardian.sln --no-restore` and
`dotnet run --project HostsGuardian.RegressionTests/HostsGuardian.RegressionTests.csproj`.
The dependency-free regression executable uses temporary hosts fixtures, in-memory rules,
reserved .invalid names, and an HTTP mock. It does not start the Engine or change real policy.

## Deferred

At this milestone, Phase 3 onward had not yet been implemented. dnsmasq orchestration, empty-token API bypass, Engine
persistence, TCP/port-53 deployment, full operational GUI state, broad discovery improvements,
and the obsolete Console policy interface remain review items. No Ubuntu service/network change
was performed. Core still includes existing Windows-only helper implementations; the Engine
uses only platform-neutral normalization from Core. Platform separation needs Phase 3 review.
