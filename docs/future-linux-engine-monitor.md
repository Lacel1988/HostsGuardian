# Future Linux Engine Monitor — deferred

Implement only after Phase 5 stabilizes the Engine runtime/status model.
This monitor is intended for the Linux machine running HostsGuardian.DnsEngine.
It provides read-only operational monitoring, not another policy-management GUI.
Windows WPF remains the primary user-facing control plane.

Potential information:
- Engine running state and uptime
- DNS UDP/TCP listener state
- Management HTTPS listener state
- Upstream DNS health
- Loaded rule count
- Query/block statistics
- Recent operational errors/logs
- Last successful Windows management-client communication

Local operational actions such as restarting the Engine may be considered later,
with explicit authorization and an operational boundary separate from policy.
No domain/device policy editing, credential generation, competing filtering
implementation or independently maintained management state.
No monitor code, service, deployment, or restart action is implemented here.
