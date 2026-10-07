# Dual-stack DNS and coverage acceptance

The Engine uses one exclusive dual-mode UDP socket and one exclusive dual-mode TCP socket. Both accept IPv4 and IPv6 through the same request processor, admission limits, policy, Safe Mode and persistence. IPv4-mapped peers are normalized to IPv4 before identity attribution. IPv6 source addresses remain evidence, never permanent DeviceIds.

`EnableIpv6Dns` defaults to true. Explicit false supports IPv4-only operation without changing host networking. Unsupported OS capability is NotApplicable; IPv6 bind failure falls back to IPv4 and reports Faulted/Degraded and listener health failure. No listener failure is hidden as full protection.

DNS status reports IPv4 and IPv6 transport states separately. Coverage is independent: healthy sockets do not establish router steering. COMPLETE requires assessed conventional paths and absence of known alternate conventional resolver paths within that scope; encrypted DNS is never guaranteed. Production has no confirmed router/phone advertisement assessment and therefore does not claim COMPLETE.

Passive evidence reads local OS interfaces and, on Linux where present, bounded NetworkManager cached DHCPv6 lease files. It sends no packets and changes no configuration. These cached Engine-host resolvers are not current RA/RDNSS evidence or another client's resolver choice. Missing evidence stays Unknown. No router impersonation, IPv6 disabling or automatic configuration occurs.

WPF keeps Engine/authentication/DNS/filtering/policy/upstream independent and adds coverage with investigation guidance. Health export includes evidence. Monitor shows both address families and coverage separately from health. Device diagnostics uses independently scrollable source/detail panes, keeps ranked unknown rows and technical caveats, and has no management actions.

Real phone acceptance remains pending: verified IPv4 DHCP advertises Vivo, but Samsung produced no matching port-53 packets; encrypted DNS/VPN/proxy settings were off. IPv6 is active. Cached host DHCPv6 points elsewhere, while passive RA capture was inconclusive. Adding IPv6 listeners does not demonstrate phone resolver steering.

Deployment readiness must require actual IPv4/IPv6 UDP/TCP responses, expected process ownership, authenticated HTTPS and preservation. Bounded polling retains every attempt. Rollback verifies the prior candidate's original capability, not new IPv6 requirements. Production installation remains a human gate.
