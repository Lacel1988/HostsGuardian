# Phase 4 GUI polish

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

The connection dialog uses scoped dark controls, visible focus/disabled states,
green success/enrollment, amber pending warnings and red errors. Sections separate
endpoint, security, connection testing and the fixed Save/Cancel footer.
Stored tokens are not displayed; first-time state is Not configured, distinct from
protected-storage errors. Enrollment state distinguishes absent, valid enrolled,
and invalid/unavailable data, with public SHA-256 fingerprint and expiry details.
The certificate status is presentation only and does not replace live validation.
The main API display derives the HTTPS endpoint using the same endpoint builder
as management requests; legacy HTTP config is not presented as active transport.

Authentication, TLS validation, DPAPI, migration, Test and Save workflows are
unchanged. No network/system changes, provisioning, deployment or Phase 5 work.
The future Linux monitor requirement is recorded separately and deferred.
