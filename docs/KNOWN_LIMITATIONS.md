# Known Limitations

## Production acceptance

Status remains **COMMITTED / PARTIAL GO**. Live Admin authentication and global block/restore have evidence. Production Operator/Observer sessions are **NOT TESTED — no applicable accounts**. New isolated RBAC passes do not substitute for those sessions. Device-specific policy and identity support exist, but exclusive live enforcement and unaffected-control-client acceptance require their own controlled test.

## DNS coverage and application behavior

- Policy applies only to DNS queries that reach the Engine and match its rules.
- Cached addresses and existing application connections may outlive a new DNS block.
- IPv6 resolver selection, alternative DNS and DoH can provide other paths; bypass must be proved rather than assumed.
- Blocking one domain does not establish complete blocking of a multi-domain service.
- Passive LAN/identity evidence is incomplete; missing observations do not prove absence or bypass.

## WPF, monitoring and AI

One historical live WPF run missed a short disabled interval between polls; the observer correctly stopped. Audit and later persistent-state/DNS checks provided complementary evidence, but not every historical intermediate revision has its own API/DNS sample. New isolated WPF checks do not erase that record.

Activity, Security Insights and the AI analyst require further intended-environment acceptance. Analyst contracts do not establish a fully deployed AI service. A newly accepted standalone GTK4 monitoring GUI is not established by this archive. Native DPI/multi-monitor acceptance was not rerun during source consolidation.

## Source packaging and history

This is a deliberate derivative of RC.2, not byte-identical deployed source. Full-checkout regressions include two explicitly historical WPF source checks; the portable RC.2 Engine check now resolves its own source correctly. The imported layout builds and tests successfully with that documented dependency. Bit-for-bit binary reproducibility and portable one-command deployment are not claimed.

An older personal test-display label remains in public Git ancestry. Current files are cleaned; history is preserved. [Provenance](RELEASE_PROVENANCE.md) records this residual exposure and the intentional deltas.
