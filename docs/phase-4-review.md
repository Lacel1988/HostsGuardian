# Phase 4 implementation and deployment boundary

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

Management uses Kestrel HTTPS on TCP 3000, explicit IP binding (loopback default),
and authentication before request-body processing on all paths. Credentials are
32 cryptographically random bytes represented by exactly 64 hexadecimal characters.
No provisioning endpoint or production credential generator is included.
Missing/unreadable/invalid token or certificate prevents API startup; Program starts
DNS only after successful management startup. DNS remains independent of request authentication.
Bodies are limited to 64 KiB, headers to 16 KiB; duplicate authorization and malformed
policy input are rejected. Engine exceptions and client response bodies are not exposed.

Deployment inputs: HOSTSGUARDIAN_API_BIND, HOSTSGUARDIAN_CREDENTIAL_FILE,
HOSTSGUARDIAN_CERTIFICATE_FILE, HOSTSGUARDIAN_CERTIFICATE_KEY_FILE. If the credential
path is absent, CREDENTIALS_DIRECTORY/management-token is used. Secret values are
not environment variables. The certificate and key use PEM files. Deployment must
restrict these files and run under a dedicated service account; no system changes
or production provisioning have been performed here.

Windows credentials use DPAPI CurrentUser under LocalAppData/HostsGuardian/credentials,
identified by random GUIDs. Ordinary config holds address, port, credential ID, and
the explicitly enrolled public certificate as Base64 DER. Existing tokens are not
redisplayed. Same-user malware or administrators remain outside the protection boundary.

Explicit migration reads the old plaintext field without putting it in the ordinary
model, writes and verifies DPAPI protection, then atomically replaces config without
the plaintext field. Protection/config-write failure retains the original config.
Ordinary Save refuses to erase a legacy credential implicitly. Incompatible older
credentials require explicit replacement with an already provisioned token through
the dialog; this does not rotate the Engine token. Old backups require separate rotation.
Failed saves may leave an unreferenced protected credential or nonsecret temporary
config file; neither silently authorizes a client.

Certificate enrollment imports only a public certificate after explicit independent
SHA-256 fingerprint verification. HTTPS requires exact enrolled DER identity,
hostname/IP SAN matching, validity and server-auth EKU, plus an explicit-trust chain.
No system trust-store installation, first-contact trust, redirect following, HTTP
fallback or validation bypass. Local enrolled certificates have no revocation service;
replacement/revocation requires local re-enrollment/removal. Renewal is manual.

TEST CONNECTION uses a draft snapshot and authenticated GET health/status, never
saves settings or policy. Results distinguish credential, network, timeout, trust,
authentication, incompatibility and Engine errors. Transport does not imply filtering
or rule synchronization. Endpoint changes require explicit credential reassociation.
Save is independent of Test and never pushes rules. Clear removes only the local
credential. Cancel leaves saved settings alone. Explicit migration is a separate action.

Tests use temporary certificates/credentials, DPAPI fixture files and high loopback
ports; the DNS fixture upstream also targets loopback. No production port 53 is bound.
UI interaction still needs human review; source/build and service-level tests do not
prove visual layout or every manual dialog interaction.

Remaining limits: token possession is not executable identity; no token rotation API,
rate limiter, roles, certificate automation or enterprise PKI; no guaranteed managed
memory erasure. Firewall restrictions, Linux file permissions, service capabilities,
certificate installation and actual deployment remain explicitly separate work.
Policy persistence, TCP DNS, startup policy restore and forwarding reliability remain
Phase 5, untouched. Full state redesign remains Phase 6. dnsmasq remains absent.
