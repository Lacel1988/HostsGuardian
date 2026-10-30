"""Bounded AI-owned metadata journals; no chat/evidence content or broad deletion."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import heapq
import logging
import os
from pathlib import Path
import stat
import threading
from typing import Literal

from pydantic import AwareDatetime, Field

from .schemas import Contract, Outcome

FILES = {"dns_activity": "dns-activity.jsonl", "device_identity": "device-identity.jsonl",
         "diagnostic": "diagnostic.jsonl", "ai_error": "ai-errors.jsonl"}
SOURCES = {"engine_status", "policy_status", "device_identity_status", "dns_activity_summary",
           "knowledge_retrieval", "structured_diagnostic_summary", "local_generation", "workflow", "http_api"}
REASONS = {"stop", "length", "invalid_request", "request_timeout", "internal_error", "workflow_capacity",
           "workflow_timeout", "workflow_step_limit", "invalid_source", "duplicate_document", "corrupt_index",
           "incompatible_index", "embedding_unavailable", "embedding_timeout", "embedding_invalid",
           "embedding_busy", "index_busy", "index_unavailable", "stale_corpus"}


class LogEvent(Contract):
    schema_version: Literal[1] = 1
    kind: Literal["dns_activity", "device_identity", "diagnostic", "ai_error"]
    timestamp: AwareDatetime
    source: str = Field(pattern=r"^[a-z_]{1,64}$")
    status: Outcome | Literal["error"]
    reason_code: str | None = Field(default=None, max_length=128)
    evidence_count: int = Field(default=0, ge=0, le=24)


class RetentionStore:
    def __init__(self, settings, directory=None, clock=None):
        self.settings = settings
        self.directory = Path(directory) if directory is not None else Path(__file__).resolve().parents[1] / "local-data/retention"
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._counts = {kind: 0 for kind in FILES}
        self.available = True
        self.expired = self.evicted = self.invalid = 0
        self.oversized_files = 0
        # Reserve one journal's space for atomic compaction, including temp bytes.
        self.file_cap = min(settings.retention_max_file_bytes, settings.retention_max_total_bytes // (len(FILES)+1))

    def _guard(self, path):
        # Reject Windows junctions/reparse points and symlinks in every ancestor.
        for candidate in (path, *path.parents):
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise OSError("Unsafe log path")
            if candidate == path and not stat.S_ISREG(info.st_mode) and candidate != self.directory:
                raise OSError("Invalid log file")
            if candidate == path and stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                raise OSError("Hard-linked log file is not owned")

    @staticmethod
    def _header(kind):
        return (json.dumps({"format":"hostsguardian-ai-metadata-log","schema_version":1,"kind":kind},sort_keys=True)+"\n").encode()

    def _path(self, kind):
        if kind not in FILES:
            raise ValueError("Unknown log category")
        path = self.directory / FILES[kind]
        self._guard(self.directory)
        self._guard(path)
        return path

    def _hours(self, kind):
        return {"dns_activity": self.settings.dns_log_retention_hours,
                "device_identity": self.settings.identity_log_retention_hours,
                "diagnostic": self.settings.diagnostic_log_retention_hours,
                "ai_error": self.settings.ai_error_retention_hours}[kind]

    def _remove_owned_temporary(self,kind,path):
        self._guard(path)
        if path.exists():
            with path.open("rb") as stream:
                if stream.readline(2049)!=self._header(kind):
                    raise OSError("Unrecognized temporary file; preserve")
            path.unlink()

    def _valid_time(self, event, now):
        return now-timedelta(hours=self._hours(event.kind)) < event.timestamp <= now+timedelta(minutes=1)

    def _read(self, kind, now):
        path = self._path(kind)
        if not path.exists():
            return []
        records = []
        sequence = 0
        with path.open("rb") as stream:
            if stream.readline(2049) != self._header(kind):
                raise OSError("Unrecognized file; preserve without modification")
            size = os.fstat(stream.fileno()).st_size
            # Oversized owned logs are compacted from a bounded tail, not read into RAM.
            start = max(0, size-max(self.file_cap*2, 4096))
            if start:
                self.oversized_files += 1
                stream.seek(start)
                stream.readline(2049)
            while True:
                line = stream.readline(2049)
                if not line:
                    break
                if len(line) > 2048:
                    self.invalid += 1
                    continue
                try:
                    event = LogEvent.model_validate_json(line)
                    if event.kind != kind or event.source not in SOURCES or (event.reason_code is not None and event.reason_code not in REASONS):
                        raise ValueError()
                    if self._valid_time(event, now):
                        sequence += 1
                        entry = (event.timestamp, sequence, event)
                        if len(records) == self.settings.retention_max_events:
                            self.evicted += 1
                            if entry > records[0]:
                                heapq.heapreplace(records, entry)
                        else:
                            heapq.heappush(records, entry)
                    else:
                        self.expired += 1
                except ValueError:
                    self.invalid += 1
        return [event for _,_,event in sorted(records)]

    def _write(self, kind, records):
        path = self._path(kind)
        temporary = path.with_name(path.name + ".tmp")
        # Only this exact owned temporary filename may be removed after a crash.
        self._remove_owned_temporary(kind,temporary)
        header = self._header(kind)
        chosen, size = [], len(header)
        for event in sorted(records, key=lambda e: e.timestamp, reverse=True):
            line = (event.model_dump_json()+"\n").encode("utf-8")
            if len(chosen) >= self.settings.retention_max_events or size+len(line) > self.file_cap:
                self.evicted += 1
                continue
            chosen.append(line)
            size += len(line)
        with temporary.open("xb") as stream:
            stream.write(header)
            for line in reversed(chosen):
                stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        self._guard(path)
        os.replace(temporary, path)
        self._counts[kind] = len(chosen)

    def cleanup(self):
        with self._lock:
            try:
                self._guard(self.directory)
                self.directory.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.available = False
                return
            now = self.clock()
            healthy = True
            blocked = set()
            # Remove only recognized leftovers before creating any new temporary.
            for kind in FILES:
                try:
                    path = self._path(kind)
                    self._remove_owned_temporary(kind,path.with_name(path.name+".tmp"))
                except OSError:
                    healthy = False
                    blocked.add(kind)
            for kind in FILES:
                if kind in blocked:
                    continue
                try:
                    path = self._path(kind)
                    if path.exists():
                        self._write(kind, self._read(kind, now))
                except OSError:
                    healthy = False
            self.available = healthy

    def record(self, kind, source, status, reason_code=None, evidence_count=0, timestamp=None):
        if source not in SOURCES:
            raise ValueError("Unknown log source")
        event = LogEvent(kind=kind, timestamp=timestamp or self.clock(), source=source, status=status,
                         reason_code=reason_code if reason_code in REASONS else None, evidence_count=evidence_count)
        now = self.clock()
        if not self._valid_time(event, now):
            self.expired += 1
            return
        with self._lock:
            try:
                path = self._path(kind)
                self.directory.mkdir(parents=True, exist_ok=True)
                line = (event.model_dump_json()+"\n").encode("utf-8")
                size = path.stat().st_size if path.exists() else 0
                if size:
                    with path.open("rb") as stream:
                        if stream.readline(2049) != self._header(kind):
                            raise OSError("Unrecognized file; preserve without modification")
                else:
                    size = len(self._header(kind))
                if size+len(line) > self.file_cap or self._counts[kind] >= self.settings.retention_max_events:
                    self._write(kind, self._read(kind, now)+[event])
                else:
                    with path.open("ab") as stream:
                        if stream.tell() == 0:
                            stream.write(self._header(kind))
                        stream.write(line)
                    self._counts[kind] += 1
            except OSError:
                self.available = False

    def read(self, kind):
        with self._lock:
            return tuple(self._read(kind, self.clock()))

    async def periodic(self,on_cleanup=None):
        while True:
            await asyncio.sleep(self.settings.retention_cleanup_seconds)
            await asyncio.to_thread(self.cleanup)
            if on_cleanup is not None:
                on_cleanup()


class MetadataErrorHandler(logging.Handler):
    def __init__(self, store):
        super().__init__(level=logging.ERROR)
        self.store = store

    def emit(self, record):
        # Never format messages, exception bodies, prompts, headers or evidence.
        try:
            self.store.record("ai_error", "workflow", "error",
                timestamp=datetime.fromtimestamp(record.created, timezone.utc))
        except (ValueError,OSError,OverflowError):
            self.store.available = False
