# v0.3.0 — accepted development checkpoint

[English landing page](../README.md) | [Magyar](../README.hu.md)

**Pre-1.0; not production-ready.** Product version is 0.3.0; the approved annotated checkpoint tag is v0.3.0. Monitor source/package identity is the accepted 0.3.0+unified1. The historical Engine assembly label shown in screenshots is not the product checkpoint identifier. No product version metadata or feature was changed by this documentation gate.

## Scope and evidence

POST-5E-7 integrated DNS/device policy and HOSTS retirement, Windows Control Center localization/notification foundation and Hungarian polish, plus the accepted Unified Linux Monitor and additive Engine telemetry/incident publisher source. WPF remains policy control; Engine executes/analyzes; Monitor provides local operations/diagnostics. The accepted Windows WPF variant is retained; candidate automatic operational-event polling and its extra WPF contract-test project were not integrated.

Accepted candidate transfer SHA-256: `72b9ffec76f14e9c063e5afc7875a12f46f141b25de467ced013d71114dceefb`.
Accepted Monitor package SHA-256: `4b1be4d4dc6008e6e956429da3a354f036ba21a4d5c63f1b8a95529c06547280`.
Preserved checksums and all 201 source-manifest entries verified. The source patch applies to the clean base. Reconciliation verified 19 Monitor files and the 93 combined Monitor/Core/Engine files against the accepted manifest, plus matching Debian payload contents. Package binaries, transfer archives, production configuration and raw runtime evidence are intentionally not repository assets. Rebuilding a native Debian package on Windows was not performed; toolchain-independent binary identity is not claimed.

On 2026-10-05: **202 Core/Engine regression groups PASS; 11 WPF groups PASS; Monitor 31 PASS and 11 GTK/platform skips on Windows; solution rebuild 0 errors** (10 existing warning occurrences). Monitor tests run from linux-monitor. Skips are not failures or executed Linux GUI tests.

Vivo Unified Monitor deployment/runtime acceptance: **PASS within documented coverage**, including installed module identity, fresh Engine-owned evidence, real GUI Stop/Start/Restart with confirmation and existing systemd D-Bus/polkit path, and independent Engine lifetime. Existing authorization can be cached; a new password prompt on every action is not promised.

Windows WPF human/runtime acceptance: **PASS within documented coverage**: normal launch, all four tabs, EN/HU persistence, secure Engine connection, truthful state expiry, Safe Mode cancel/enter/exit, draft/unsent state, audit and GUI close/reopen independence. Empty production devices/bindings were truthful, not populated-device acceptance. Accidental repeated explicit policy deliveries were reconciled and accepted as HUMAN TEST ACTION, not a product defect. Baseline production-policy preservation across those human actions is not claimed, and no restoration was performed as part of the accepted checkpoint.

## Remaining boundaries

- Phase 5E-8 whole-LAN/router-DHCP acceptance remains pending and paused.
- Natural DNS traffic and real incident-delivery coverage remain incomplete where documented; no synthetic production incidents were created to force acceptance.
- Populated real-device policy acceptance remains pending; IPv6 device enforcement and proxy/NAT identity recovery are not claimed.
- NeedDaemonReload=yes is a known deployment caveat under investigation, preserved and not changed during these gates. It is not a source-commit blocker; no daemon-reload is authorized here.
- Native Windows toast activation remains deferred; in-app notifications are available. Historical raw messages/OS exceptions are not translated retrospectively.
- Autostart configuration inspection does not substitute for logout/reboot acceptance. The Windows DNS interface inventory had a transient missing interface; full inventory preservation was not asserted.
- Log newest-first ordering (including after severity filtering) is UX backlog, not implemented. Broader desktop automation/accessibility coverage remains future work.

Before future authorized Git staging, preserve executable mode for linux-monitor/debian/rules and linux-monitor/packaging/hostsguardian-monitor. Documentation does not authorize staging, commit, push, tagging, deployment, policy restoration, or system/network changes.
