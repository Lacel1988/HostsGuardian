"""Explicitly authorized, GET-only snapshot collection; never certifies DNS enforcement."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

from .engine import (EngineConfig, EngineHTTPS, EngineReadError, Health, DnsStatus,
                     PolicyRead, Bindings, Activity, Diagnostics, parse_wire, fingerprint)


async def collect(config):
    client = EngineHTTPS(config)
    models = {"/health": Health, "/dns/status": DnsStatus, "/v2/policy": PolicyRead,
              "/v2/bindings": Bindings, "/v3/activity": Activity, "/v2/diagnostics": Diagnostics}
    snapshots = []
    for phase in ("before", "after"):
        snapshot = {"phase": phase, "reads": {}}
        for path in (*models, "/v2/capabilities"):
            try:
                raw, received = await client.get(path)
                if path in models:
                    parse_wire(models[path], raw)
                elif type(raw.get("apiVersion")) is not int or raw["apiVersion"] != 2:
                    raise ValueError("Unsupported capabilities version")
                item = {"status": "success", "received_at": received.isoformat()}
                source_time = raw.get("snapshotUtc", raw.get("observedAtUtc"))
                if source_time is not None:
                    observed = datetime.fromisoformat(source_time.replace("Z", "+00:00"))
                    age = (received-observed).total_seconds()
                    item.update(source_timestamp=source_time, age_seconds=round(age, 3),
                                fresh=-5 <= age <= config.max_age_seconds)
                if path == "/health":
                    item["ok"] = raw["ok"]
                elif path == "/dns/status":
                    item["configuration"] = {k: raw[k] for k in (
                        "dnsPort", "udpListening", "tcpListening", "filteringEnabled",
                        "emergencySafeMode", "policyRevision", "instanceId")}
                    item["configuration_sha256"] = fingerprint(item["configuration"])
                elif path == "/v2/policy":
                    item.update(policy_sha256=fingerprint(raw["policy"]), revision=raw["revision"],
                                instance_id=raw["instanceId"])
                elif path == "/v2/bindings":
                    item.update(generation=raw["generation"], observations=len(raw["observations"]),
                                independently_verified_identity=False)
                elif path == "/v3/activity":
                    item["buckets"] = len(raw["buckets"])
                snapshot["reads"][path] = item
            except EngineReadError as exc:
                snapshot["reads"][path] = {"status": exc.outcome.value, "reason_code": exc.code}
            except (ValueError, TypeError, KeyError):
                snapshot["reads"][path] = {"status": "invalid_response", "reason_code": "adapter:invalid_response"}
        snapshots.append(snapshot)
    before, after = [s["reads"] for s in snapshots]
    comparisons = {}
    for path, key in (("/dns/status", "configuration_sha256"), ("/v2/policy", "policy_sha256")):
        comparisons[path] = before[path].get(key) == after[path].get(key) if key in before[path] and key in after[path] else None
    return {"gate4": "NO-GO", "origin": config.origin, "snapshots": snapshots,
            "unchanged_fingerprints": comparisons,
            "limitations": ["Csak hitelesített API-jelentések; két pillanatkép nem teljes stabilitásmérés.",
                "A DNS UDP/TCP kontrollmérés és az engedélyezett kliensoldali blokkolási ellenőrzés külön szükséges.",
                "Eszközönkénti enforcement nem igazolt. Ez a gyűjtő nem ad automatikus PASS minősítést."]}


def main():
    parser = argparse.ArgumentParser(description="Gate 4: külön engedélyezett, csak olvasó élő pillanatképek")
    parser.add_argument("--authorized-live-read", action="store_true")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--certificate-file", required=True, type=Path)
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--token-format", choices=("hex","dpapi-current-user"), default="hex")
    args = parser.parse_args()
    if not args.authorized_live_read:
        parser.error("Élő hozzáféréshez előzetes felhasználói engedély és --authorized-live-read szükséges.")
    config = EngineConfig(origin=args.origin, certificate_file=args.certificate_file,
        certificate_sha256=args.certificate_sha256, token_file=args.token_file, token_format=args.token_format)
    print(json.dumps(asyncio.run(collect(config)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
