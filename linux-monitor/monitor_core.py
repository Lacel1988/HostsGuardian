"""Bounded local status parsing and fixed-unit recovery contracts. No GTK dependency."""
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

UNIT = "hostsguardian-engine.service"  # Deployment must verify this exact unit on Vivo.
STATUS_PATH = Path("/run/hostsguardian-monitor/status.json")
CONTROL_METHODS = {"start": "StartUnit", "stop": "StopUnit", "restart": "RestartUnit"}
MAX_BYTES = 131072


def control_request(verb):
    if verb not in CONTROL_METHODS:
        raise ValueError("Unsupported recovery action")
    return CONTROL_METHODS[verb], (UNIT, "replace")


def parse_snapshot(raw, main_pid, now=None):
    if len(raw) > MAX_BYTES:
        raise ValueError("Status too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate status field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if value.get("schemaVersion") != 1 or type(value.get("processId")) is not int or value["processId"] != main_pid or main_pid <= 0:
        raise ValueError("Wrong schema or service instance")
    timestamp = datetime.fromisoformat(value["emittedAtUtc"].replace("Z", "+00:00"))
    age = ((now or datetime.now(timezone.utc)) - timestamp).total_seconds()
    if age < -2 or age > 10:
        raise ValueError("Stale status")
    status_value = value.get("status")
    if not isinstance(status_value, dict) or status_value.get("implementation") != "HostsGuardian.DnsEngine":
        raise ValueError("Invalid status")
    for field in ("udpState", "tcpState", "managementState"):
        if status_value.get(field) not in ("NotStarted", "Starting", "Listening", "Stopped", "Faulted"):
            raise ValueError("Invalid listener evidence")
    for field in ("filteringEnabled", "emergencySafeMode", "policyLoaded"):
        if type(status_value.get(field)) is not bool:
            raise ValueError("Missing filtering evidence")
    if status_value["filteringEnabled"] != (status_value["policyLoaded"] and not status_value["emergencySafeMode"]):
        raise ValueError("Contradictory filtering state")
    for field in ("committedRuleCount", "activeRuleCount"):
        if type(status_value.get(field)) is not int or status_value[field] < 0:
            raise ValueError("Invalid rule counts")
    if status_value["activeRuleCount"] != (status_value["committedRuleCount"] if status_value["filteringEnabled"] else 0):
        raise ValueError("Contradictory rule counts")
    events = value.get("events")
    if not isinstance(events, list) or len(events) > 64:
        raise ValueError("Invalid events")
    for event in events:
        if not isinstance(event, dict) or any(not isinstance(event.get(key), str) or len(event[key]) > limit for key, limit in (("level", 10), ("component", 40), ("message", 240))):
            raise ValueError("Invalid event")
    return value


def read_snapshot(path, main_pid, now=None, expected_uid=None):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Symlink status is refused")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("Unsafe status permissions")
        if expected_uid is not None and info.st_uid != expected_uid:
            raise ValueError("Status owner differs from Engine")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(MAX_BYTES + 1)
        return parse_snapshot(raw, main_pid, now)
    finally:
        os.close(descriptor)


def upstream_state(status_value, now=None):
    outcome = status_value.get("lastUpstreamOutcome", "NotObserved")
    if outcome == "NotObserved":
        return "Unknown"
    field = "lastUpstreamSuccessUtc" if outcome == "Response" else "lastUpstreamFailureUtc"
    observed = status_value.get(field)
    if observed is None:
        return "Unknown"
    timestamp = datetime.fromisoformat(observed.replace("Z", "+00:00"))
    age = ((now or datetime.now(timezone.utc)) - timestamp).total_seconds()
    if age < -2 or age > 30:
        return "Unknown (observation stale)"
    if outcome == "Response":
        return "Degraded (fallback used)" if status_value.get("lastUpstreamRequestUsedFallback") else "Healthy"
    return "Failed (latest passive observation)"


def describe(unit, snapshot):
    active = unit.get("ActiveState", "unknown")
    engine = {"active": "Running", "inactive": "Stopped", "failed": "Failed", "activating": "Starting", "deactivating": "Stopping"}.get(active, "Unknown")
    if active == "active" and (unit.get("SubState") != "running" or unit.get("MainPID", 0) <= 0):
        engine = "Unknown (unit active, process not established)"
    lines = [f"Engine: {engine}", f"Systemd substate: {unit.get('SubState', 'unknown')}"]
    if snapshot is None:
        return "\n".join(lines + ["Engine diagnostics: Unknown (missing, stale or untrusted status)"])
    s = snapshot["status"]
    for label, field in (("UDP DNS", "udpState"), ("TCP DNS", "tcpState"), ("HTTPS management", "managementState")):
        lines.append(f"{label}: {s.get(field, 'Unknown')}")
    lines += [f"Filtering: {'Safe Mode bypass' if s.get('emergencySafeMode') else 'Enabled' if s.get('filteringEnabled') else 'Disabled'}",
              f"Safe Mode: {s.get('emergencySafeMode', 'Unknown')}",
              f"Policy revision: {s.get('policyRevision', 'Unknown')}",
              f"Committed/active global rules: {s.get('committedRuleCount', '?')}/{s.get('activeRuleCount', '?')}",
              f"Committed/active device overrides: {s.get('committedDeviceOverrideCount', '?')}/{s.get('activeDeviceOverrideCount', '?')}",
              f"Upstream health: {upstream_state(s)}",
              f"Persistence: {s.get('persistenceFault') or 'No reported fault'}; restore: {s.get('policyRestoreState', 'Unknown')}",
              f"Upstream latest outcome: {s.get('lastUpstreamOutcome', 'Unknown')} (passive observation)",
              f"Last start: {snapshot.get('startedAtUtc', 'Unknown')}"]
    started = datetime.fromisoformat(snapshot["startedAtUtc"].replace("Z", "+00:00"))
    lines.append(f"Uptime: {max(0, int((datetime.now(timezone.utc) - started).total_seconds()))} seconds")
    return "\n".join(lines)
