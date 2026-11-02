# RC.2 Architecture

## Responsibilities

- **Linux Engine:** executes authorized DNS rules, owns policy persistence, user/session management, API authorization and policy audit.
- **Windows WPF Control Center:** presents Engine readback and authenticated user controls. It does not become an independent DNS enforcement service.
- **Linux monitoring:** observes diagnostics and evidence. It does not acquire policy decision authority.
- **AI analyst:** analyzes authorized data and suggests investigations. It must not gain independent write authority or bypass the Engine's authorization boundaries.

Clients send DNS queries directly to the Engine. WPF uses authenticated HTTPS management; DNS does not travel through the WPF process. Systemd controls the independent Linux service lifecycle. Shared Core contracts describe policy, identity and diagnostic state.

## Domain Block List and policy

`DomainBlockList.Change` separates persisted list membership from the existing enforcement rules. Disabling a global entry removes its block while retaining its saved row; deletion is a distinct action. Device changes retain the existing Allow/Block priority rules. Inherited global blocking must remain visible in a device view. A switch's configured state, an Engine decision and a measured DNS response are separate evidence layers.

Schema v4 introduces saved-domain membership. Migration must preserve existing effective rules. Revision/instance-aware writes protect against stale mutation. Persistence and policy audit record successful commits; audit alone does not prove every client used the Engine resolver.

## Identity and authorization

LAN presence, registration, DeviceId, validated address binding and DNS enforcement are distinct. Device policy must use validated identity; never silently convert a device operation to a global one.

The Engine owns the userstore and uses Argon2id hashes, bounded login attempts and expiring sessions. First Admin initialization closes after success; the last active Admin is protected. Operators are constrained to assigned devices; Observers have system-wide read-only visibility and cannot read secret credential material. WPF visibility restrictions do not replace direct API authorization.

## Configuration boundary

The Engine entry point reads `HOSTSGUARDIAN_API_BIND`, `HOSTSGUARDIAN_CREDENTIAL_FILE`, `HOSTSGUARDIAN_CERTIFICATE_FILE`, `HOSTSGUARDIAN_CERTIFICATE_KEY_FILE`, `HOSTSGUARDIAN_POLICY_FILE`, `HOSTSGUARDIAN_USERS_FILE`, `HOSTSGUARDIAN_RBAC_REQUIRED` and `HOSTSGUARDIAN_MONITOR_STATUS_FILE`, with additional upstream and validation options in source. Values and secret files are environment-owned and excluded from publication.

For a **new** installation, `--initialize-admin <private-userstore-path>` prompts for a strong password. Use a local interactive terminal, never command-line password literals or chat. Existing production stores must not be initialized again.

Systemd unit/drop-in ownership, effective ExecStart, service User/Group access and sandbox write exceptions must be validated together. RC.2 finalization restored inherited `Restart=on-failure` through daemon-reload without restarting the Engine or writing policy. The private deployment/recovery runner is not a general public installer.

## Source entry points

Use the RC.2 projects listed in the root [README](../README.md). The import has a local `Directory.Build.props` boundary so older root version defaults are not inherited accidentally. Archived source bytes are tracked in the import manifest; the layout has now passed the builds and checks listed in [Validation](VALIDATION.md). This is buildability evidence, not a claim of bit-for-bit shipped binary reproduction.

The root `HostsGuardian.sln` is the official solution and includes only RC.2 projects. The preserved `legacy/HostsGuardian.PreRC2.sln` and root-level directories marked `README.LEGACY.md` are historical, not equal active implementations. The existing test-only historical WPF source checks retain their documented dependency without making that GUI a current build target.
