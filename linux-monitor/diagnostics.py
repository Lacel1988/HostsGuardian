"""In-memory live diagnostic history. No credentials, policy mutation or persistent history."""
import math
import time
from collections import deque
from datetime import datetime, timezone

WINDOW_SECONDS = 600
MAX_SAMPLES = 600


def finite(value, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def validate(value, now=None):
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise ValueError("Diagnostics version unavailable")
    if not isinstance(value.get("instanceId"), str) or not 1 <= len(value["instanceId"]) <= 100:
        raise ValueError("Invalid diagnostics instance")
    stamp = datetime.fromisoformat(value["snapshotUtc"].replace("Z", "+00:00"))
    age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
    if age < -2 or age > 10:
        raise ValueError("Stale diagnostics")
    counters = value["counters"]
    for field in ("received", "udp", "tcp", "allowed", "policyBlocked", "failed", "rejected", "capacityDropped", "cancelled",
                  "servfail", "upstreamAttempts", "upstreamTimeouts", "upstreamFailures", "upstreamRetries", "fallbackAttempts",
                  "tcpConnectionsRejected", "transportFailures"):
        if type(counters.get(field)) is not int or counters[field] < 0:
            raise ValueError("Invalid counter")
    for section in ("upstreamLatency", "processingLatency"):
        latency = value[section]
        if type(latency.get("samples")) is not int or not 0 <= latency["samples"] <= 2048:
            raise ValueError("Invalid latency sample count")
        for field in ("recentMs", "p50Ms", "p95Ms"):
            if latency.get(field) is not None and not finite(latency[field]):
                raise ValueError("Invalid latency")
    pressure = value["pressure"]
    for field in ("currentRequests", "peakRequests", "udpCurrent", "udpCapacity", "tcpCurrentRequests", "tcpConnections", "tcpConnectionCapacity", "capacityDrops"):
        if type(pressure.get(field)) is not int or pressure[field] < 0:
            raise ValueError("Invalid pressure")
    if not 1 <= pressure["udpCapacity"] <= 64 or pressure["tcpConnectionCapacity"] != 16:
        raise ValueError("Invalid capacity")
    resources = value["resources"]
    for field in ("uptimeSeconds", "processId"):
        if not finite(resources.get(field)):
            raise ValueError("Invalid runtime")
    if resources.get("workingSetBytes") is not None and not finite(resources["workingSetBytes"]):
        raise ValueError("Invalid memory")
    if resources.get("cpuPercent") is not None and not finite(resources["cpuPercent"]):
        raise ValueError("Invalid CPU")
    if value.get("health") not in ("Healthy", "Degraded", "Critical"):
        raise ValueError("Invalid health")
    if not isinstance(value.get("components"), list) or len(value["components"]) > 6:
        raise ValueError("Invalid components")
    for component in value["components"]:
        if not isinstance(component, dict) or component.get("component") not in ("Listeners", "Management", "Upstream", "Processing", "Capacity", "Persistence") or component.get("state") not in ("Healthy", "Degraded", "Critical"):
            raise ValueError("Invalid component evidence")
        for field, limit in (("incidentId", 140), ("sinceUtc", 50)):
            if component.get(field) is not None and (not isinstance(component[field], str) or len(component[field]) > limit):
                raise ValueError("Invalid incident evidence")
    if len({c["component"] for c in value["components"]}) != len(value["components"]):
        raise ValueError("Duplicate health component")
    if not isinstance(resources.get("revision", "unknown"), str) or len(resources.get("revision", "unknown")) > 100:
        raise ValueError("Invalid runtime revision")
    if not isinstance(value.get("resolvers"), list) or len(value["resolvers"]) > 2:
        raise ValueError("Invalid resolvers")
    return value


class LiveHistory:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.samples = deque(maxlen=MAX_SAMPLES)
        self.previous = None
        self.current = None
        self.rate = None
        self.available = False
        self.message = "Waiting for diagnostic telemetry"

    def missing(self, message="Engine diagnostics unavailable"):
        self.available = False
        self.current = None
        self.rate = None
        self.message = message
        now = self.clock()
        if not self.samples or now - self.samples[-1][0] >= .9:
            self.samples.append((now, None, None, None))
        self.previous = None
        self._trim(now)

    def _trim(self, now):
        while self.samples and now - self.samples[0][0] > WINDOW_SECONDS:
            self.samples.popleft()

    def accept(self, value, now=None):
        try:
            value = validate(value, now)
        except (ValueError, KeyError, TypeError, OverflowError):
            self.missing("Stale or invalid diagnostic telemetry")
            return False
        tick = self.clock()
        if self.previous and self.previous["instanceId"] != value["instanceId"]:
            self.samples.clear()
            self.previous = None
        if self.previous and self.previous["snapshotUtc"] == value["snapshotUtc"]:
            self.available = True
            return True  # Existing publisher refreshes every 2 s; never invent duplicate samples.
        self.rate = None
        if self.previous:
            elapsed = value["resources"]["uptimeSeconds"] - self.previous["resources"]["uptimeSeconds"]
            delta = value["counters"]["received"] - self.previous["counters"]["received"]
            if 0 < elapsed <= 10 and delta >= 0:
                self.rate = delta / elapsed
        lat = value["upstreamLatency"]
        self.samples.append((tick, self.rate, lat["p50Ms"], lat["p95Ms"]))
        self._trim(tick)
        self.previous = self.current = value
        self.available = True
        self.message = "Live • 10 minute memory window"
        return True

    @property
    def peak(self):
        return max((s[1] for s in self.samples if s[1] is not None), default=0)


def graph_scale(values, minimum):
    """Zero origin and readable ceiling; a spike stays visible for the retained window."""
    peak = max((v for v in values if v is not None), default=0)
    target = max(minimum, peak * 1.15)
    magnitude = 10 ** math.floor(math.log10(target))
    for factor in (1, 2, 5, 10):
        if factor * magnitude >= target:
            return factor * magnitude
    return 10 * magnitude
