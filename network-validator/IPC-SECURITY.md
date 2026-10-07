# NetworkValidator IPC v2 — source review

Deployment is not authorized by this document. DNS does not depend on the helper.

## Selected boundary

PID1 creates `/run/hostsguardian-validator/validator.sock`. Every ancestor is root-owned and not group/world-writable. The socket is root:Engine-group, mode 0660; its directory is root:root 0755. The existing Engine/helper service user may connect but cannot create, remove or replace the path. No new service identity or persistent-state migration is required. Group access permits connection, not authorization.

The helper consumes exactly one systemd-activated AF_UNIX listening stream FD, never binds/unlinks/chmods the socket. It checks activation variables, canonical pathname, filesystem type/ownership/permissions, and listener properties. A fake/stale/untrusted path fails closed; the installer must refuse an existing unexpected path rather than remove it blindly.

The Engine checks root-owned ancestors with no symlinks, exact socket owner/group/mode, and unchanged device/inode before/after connecting. SO_PEERCRED must identify the listener creator as PID1/root/root. Unix credentials for a listening socket are captured when it is created/listened, so the inherited listener identifies PID1, not the unprivileged Python process. An ordinary user cannot forge those kernel credentials. The Engine sends no request before the helper authorization greeting.

The helper checks kernel SO_PEERCRED plus SO_PEERPIDFD (Linux >= 6.5), then obtains the fixed Engine service MainPID through the root system bus using libsystemd. UID match alone is insufficient: another same-UID process fails the MainPID test. The socket-associated pidfd is checked for peer exit before/after manager lookup and again before validation and response. A numeric PID or caller-supplied PID file is never sufficient. Missing pidfd support or manager availability fails closed. No `/proc/<pid>/exe` dependency, ptrace capability, shell command or child process is used for authorization.

The bus address and service/unit/property are fixed; environment cannot redirect them. Root-protected libsystemd and the root system-bus endpoint are verified. The Engine publication and helper script must be root-protected, including all containing directories. Helper Python runs isolated, with loader/Python/bus override variables unset. Engine retains CAP_NET_BIND_SERVICE; helper alone receives CAP_NET_RAW, scoped by its service, never by file capabilities on Python.

## Races, restart and failure

Unprivileged path substitution is prevented by protected ancestors and verified creator credentials. An authorized root administrator can replace deployment state and is outside this boundary. Socket restart replacement between checks is rejected; a later connection may authenticate the new PID1 listener. Helper restart reuses PID1's listener. Old/exited Engine connections fail their pidfd/MainPID checks; Engine restart is accepted only at its new live MainPID. A same-UID process can attempt denial of service, including exhausting the two bounded session slots or sending signals; this architecture does not claim protection from availability attacks by the service user.

Requests are exact-target IPv4/interface only: 1024-byte frame, three-second framing deadline, two concurrent sessions without queued work, bounded rate/deduplication, two-second ARP response window, 32 received-frame budget, no capture/sweep/general packet API. ARP remains unauthenticated network evidence and conflicts fail closed.

`HOSTSGUARDIAN_VALIDATOR_SOCKET` enables authenticated health probes. Active ARP requires the separate explicit `HOSTSGUARDIAN_ACTIVE_VALIDATION=1`; absence means health-only mode and the existing passive producer remains authoritative. Helper failure never stops DNS or fabricates fresh binding. Previously confirmed active evidence still expires within its existing 45-second bound; registration/evidence changes invalidate it sooner. Health state/reason/timestamp are published for Monitor. Attempt history is bounded and oldest-attempt ordering prevents starvation.

## Topology prerequisite

Monitor declares python3-cairo and python3-gi-cairo dependencies. Without the GI Cairo bridge it avoids registering the graphical callback, explains the missing prerequisite, and keeps list/details/other pages usable. The graph remains implemented. GTK testing must realize a DrawingArea callback with the bridge, not merely invoke Cairo directly.

## Verification limit

Unprivileged tests exercise real Linux peer credentials/pidfd and the actual read-only systemd lookup, plus deterministic ownership/race/authorization/framing fixtures. Creating a root-owned socket/unit and exercising CAP_NET_RAW under the exact installed service remain privileged deployment acceptance, requiring separate approval. No source test impersonates root, installs a package, invokes sudo, probes production ARP or changes services.
