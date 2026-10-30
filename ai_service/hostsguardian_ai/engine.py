"""Authenticated, pinned HTTPS reader. No discovery, writes, redirects or DNS lookup targets."""
import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
from ipaddress import ip_address
import json
from pathlib import Path
import re
import socket
import ssl
import threading
from typing import Literal
from urllib.parse import urlsplit
import uuid

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, field_validator

from .schemas import Evidence, Outcome, ToolName, ToolResult

PATHS = frozenset({"/health", "/dns/status", "/v2/capabilities", "/v2/policy",
                   "/v2/bindings", "/v3/activity", "/v2/diagnostics"})


class EngineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    origin: str
    certificate_file: Path
    certificate_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    token_file: Path
    token_format: Literal["hex", "dpapi-current-user"] = "hex"
    timeout: float = Field(default=3, gt=0, le=10)
    max_age_seconds: int = Field(default=60, ge=1, le=300)

    @field_validator("origin")
    @classmethod
    def explicit_private_https(cls, value):
        url = urlsplit(value)
        if url.scheme != "https" or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment or not url.port:
            raise ValueError("Explicit private HTTPS origin required")
        address = ip_address(url.hostname or "")
        if not address.is_private or address.is_multicast or address.is_unspecified or address.is_link_local:
            raise ValueError("Only an explicitly selected private/loopback address is allowed")
        return value.rstrip("/")


def read_secret(path, token_format="hex"):
    info=Path(path).lstat()
    if Path(path).is_symlink() or getattr(info,"st_file_attributes",0)&0x400 or info.st_nlink>1:
        raise ValueError("Credential links are not permitted")
    with Path(path).open("rb") as stream:
        value = stream.read(16385 if token_format=="dpapi-current-user" else 257)
    if token_format=="dpapi-current-user":
        from .dpapi import unprotect_token
        return unprotect_token(value)
    if token_format!="hex":
        raise ValueError("Unsupported credential format")
    if len(value)>256:
        raise ValueError("Invalid credential file")
    token = value.decode("ascii").rstrip("\r\n")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", token):
        raise ValueError("Invalid credential file")
    return SecretStr(token)


class EngineReadError(Exception):
    def __init__(self, outcome, code):
        self.outcome, self.code = outcome, code
        super().__init__(code)


class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, *, context, fingerprint, timeout):
        super().__init__(host, port, context=context, timeout=timeout)
        self.fingerprint = fingerprint

    def connect(self):
        super().connect()  # TLS chain, validity, server purpose and IP identity first.
        peer = self.sock.getpeercert(binary_form=True)
        if not hmac.compare_digest(hashlib.sha256(peer).hexdigest(), self.fingerprint):
            self.close()
            raise ssl.SSLError("Certificate pin mismatch")
        # HTTPSConnection.send connects before transmitting any HTTP/auth bytes.


def no_duplicates(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError("Duplicate response field")
        result[key] = value
    return result


class EngineHTTPS:
    def __init__(self, config: EngineConfig):
        self.config = config
        self._token = read_secret(config.token_file,config.token_format)
        with config.certificate_file.open("rb") as stream:
            pem = stream.read(32769)
        if len(pem)>32768 or pem.count(b"-----BEGIN CERTIFICATE-----")!=1 or b"PRIVATE KEY" in pem:
            raise ValueError("One enrolled public certificate required")
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
        pin = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(pin,config.certificate_sha256.lower()):
            raise ValueError("Enrolled certificate fingerprint mismatch")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cadata=pem.decode("ascii"))
        self._slot = threading.BoundedSemaphore(1)

    def _read(self,path):
        if path not in PATHS:
            raise EngineReadError(Outcome.INVALID,"adapter:endpoint_not_allowed")
        if not self._slot.acquire(blocking=False):
            raise EngineReadError(Outcome.UNAVAILABLE,"adapter:capacity")
        url = urlsplit(self.config.origin)
        connection = PinnedConnection(url.hostname,url.port,context=self.context,
            fingerprint=self.config.certificate_sha256.lower(),timeout=self.config.timeout)
        expired = threading.Event()
        def interrupt():
            expired.set()
            try:
                if connection.sock is not None:
                    connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        timer = threading.Timer(self.config.timeout,interrupt)
        timer.daemon = True
        try:
            timer.start()
            connection.request("GET",path,headers={"Authorization":"Bearer "+self._token.get_secret_value(),
                                                    "Accept":"application/json","Connection":"close"})
            response = connection.getresponse()
            if response.status != 200:
                # No redirects and no response-body/error text is echoed.
                raise EngineReadError(Outcome.UNAVAILABLE,f"http:{response.status}")
            if response.getheader("Content-Type","").split(";",1)[0].strip()!="application/json":
                raise EngineReadError(Outcome.INVALID,"adapter:content_type")
            body = response.read(2*1024*1024+1)
            if len(body)>2*1024*1024:
                raise ValueError("Response limit")
            data = json.loads(body,object_pairs_hook=no_duplicates,parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
            if not isinstance(data,dict):
                raise ValueError("Object required")
            if expired.is_set():
                raise TimeoutError()
            return data,datetime.now(timezone.utc)
        except EngineReadError:
            raise
        except ssl.SSLError:
            raise EngineReadError(Outcome.UNAVAILABLE,"tls:verification_failed") from None
        except (TimeoutError,socket.timeout):
            raise EngineReadError(Outcome.TIMEOUT,"adapter:timeout") from None
        except (OSError,http.client.HTTPException):
            raise EngineReadError(Outcome.TIMEOUT if expired.is_set() else Outcome.UNAVAILABLE,
                                  "adapter:timeout" if expired.is_set() else "adapter:connection_failed") from None
        except (ValueError,UnicodeError):
            raise EngineReadError(Outcome.INVALID,"adapter:invalid_json") from None
        finally:
            timer.cancel()
            connection.close()
            self._slot.release()

    async def get(self,path):
        if path not in PATHS:
            raise EngineReadError(Outcome.INVALID,"adapter:endpoint_not_allowed")
        return await asyncio.to_thread(self._read,path)


class Wire(BaseModel):
    model_config=ConfigDict(extra="ignore",strict=True)


def parse_wire(model,raw):
    # Strict JSON accepts RFC3339 timestamps, while rejecting stringified numbers/bools.
    if any(key in raw and type(raw[key]) is not int for key in ("schemaVersion","apiVersion")):
        raise ValueError("Integer version required")
    return model.model_validate_json(json.dumps(raw,allow_nan=False))


class Health(Wire):
    ok: bool
    engine: Literal["HostsGuardian.DnsEngine"]
    apiVersion: Literal[1]


class DnsStatus(Wire):
    snapshotUtc: AwareDatetime
    instanceId: str = Field(min_length=1,max_length=128)
    dnsPort: int = Field(ge=1,le=65535)
    udpListening: bool
    tcpListening: bool
    filteringEnabled: bool
    emergencySafeMode: bool
    policyRevision: int | None = Field(ge=0)
    upstreamHealth: str = Field(max_length=64)


class Policy(Wire):
    schemaVersion: Literal[2,3]
    globalBlockedDomains: list[str] = Field(max_length=4096)
    devices: list[dict] = Field(max_length=4096)
    overrides: list[dict] = Field(max_length=4096)


class PolicyRead(Wire):
    revision: int | None = Field(ge=0)
    policy: Policy
    instanceId: str = Field(min_length=1,max_length=128)


class Binding(Wire):
    address: str = Field(max_length=64)
    networkScope: str | None = Field(max_length=128)
    deviceId: str = Field(max_length=64)
    observedAtUtc: AwareDatetime
    expiresAtUtc: AwareDatetime
    validated: bool

    @field_validator("address")
    @classmethod
    def address_valid(cls,value):
        ip_address(value)
        return value

    @field_validator("deviceId")
    @classmethod
    def device_valid(cls,value):
        uuid.UUID(value)
        return value


class Bindings(Wire):
    generation: int = Field(ge=0)
    observations: list[Binding] = Field(max_length=4096)


class Bucket(Wire):
    windowStartUtc: AwareDatetime
    allowed: int = Field(ge=0)
    blocked: int = Field(ge=0)
    failed: int = Field(ge=0)


class Activity(Wire):
    schemaVersion: Literal[1]
    observedAtUtc: AwareDatetime
    retentionHours: Literal[24]
    maximumBuckets: Literal[256]
    buckets: list[Bucket] = Field(max_length=256)


class Diagnostics(Wire):
    schemaVersion: Literal[1]
    instanceId: str = Field(min_length=1,max_length=128)
    snapshotUtc: AwareDatetime
    health: str = Field(max_length=64)
    counters: dict


class EngineEvidence(Evidence):
    fact_type: Literal["engine_health","dns_status","policy_status","binding_status","activity_summary"]
    received_at: AwareDatetime
    source_timestamp: AwareDatetime | None = None
    freshness: Literal["fresh","stale","unknown"]
    network_scope: str | None = Field(default=None,max_length=128)
    device_id: str | None = Field(default=None,max_length=64)
    binding_state: Literal["fresh_reported","stale","unvalidated","ambiguous","missing"] | None = None
    instance_id: str | None = Field(default=None,max_length=128)
    facts: dict[str,bool|int|str|None] = Field(max_length=16)
    valid_until: AwareDatetime | None = None


class EngineToolResult(ToolResult):
    reason_code: str | None = None


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


class EngineDiagnosticsAdapter:
    """Approved operation mapping. 'Verified' means authenticated reported facts, not device enforcement proof."""
    def __init__(self,config,client=None):
        self.config=config
        self.client=client or EngineHTTPS(config)

    def accepts(self,item):
        return isinstance(item,EngineEvidence) and item.source_reference.startswith(self.config.origin+"/") and item.source_reference[len(self.config.origin):] in PATHS

    def _fresh(self,observed,received):
        age=(received-observed).total_seconds()
        return -5<=age<=self.config.max_age_seconds

    def _evidence(self,tool,path,received,kind,facts,observed=None,instance=None,revision=None,**extra):
        fresh=self._fresh(observed,received) if observed is not None else None
        # Bindings never establish physical identity; activity never proves client receipt.
        verification="verified" if kind!="binding_status" and fresh is not False else "unverified"
        content=json.dumps({"reported_by_authenticated_api":True,"fact_type":kind,**facts},sort_keys=True,ensure_ascii=False)
        return EngineEvidence(evidence_id="engine:"+fingerprint([tool.value,path,received.isoformat(),facts])[:48],
            source_component="authenticated-engine-api",timestamp=observed or received,observation=content,
            verification=verification,source_reference=self.config.origin+path,policy_revision=revision,
            limitation="Authenticated API report only; no end-to-end or per-device enforcement proof.",
            fact_type=kind,received_at=received,source_timestamp=observed,freshness="fresh" if fresh else "stale" if fresh is False else "unknown",
            instance_id=instance,facts=facts,**extra)

    async def read(self,tool):
        evidence=[]
        try:
            if tool==ToolName.ENGINE:
                raw,received=await self.client.get("/health"); health=parse_wire(Health,raw)
                evidence.append(self._evidence(tool,"/health",received,"engine_health",{"ok":health.ok}))
                raw,received=await self.client.get("/dns/status"); status=parse_wire(DnsStatus,raw)
                evidence.append(self._evidence(tool,"/dns/status",received,"dns_status",
                    {"udp_listening":status.udpListening,"tcp_listening":status.tcpListening,"dns_port":status.dnsPort,
                     "filtering_enabled":status.filteringEnabled,"safe_mode":status.emergencySafeMode,"upstream_health":status.upstreamHealth},
                    observed=status.snapshotUtc,instance=status.instanceId,revision=status.policyRevision))
            elif tool==ToolName.POLICY:
                raw,received=await self.client.get("/v2/policy"); policy=parse_wire(PolicyRead,raw)
                # Full policy payload is fingerprinted locally; names, domains and MACs are not forwarded to a model/log.
                policy_hash=fingerprint(raw["policy"])
                status_raw,status_received=await self.client.get("/dns/status"); status=parse_wire(DnsStatus,status_raw)
                if policy.instanceId!=status.instanceId or policy.revision!=status.policyRevision:
                    raise EngineReadError(Outcome.INSUFFICIENT,"adapter:inconsistent_snapshot")
                if not self._fresh(status.snapshotUtc,status_received):
                    raise EngineReadError(Outcome.INSUFFICIENT,"adapter:stale_data")
                evidence.append(self._evidence(tool,"/v2/policy",received,"policy_status",
                    {"schema_version":policy.policy.schemaVersion,"global_rule_count":len(policy.policy.globalBlockedDomains),
                     "registered_device_count":len(policy.policy.devices),"override_count":len(policy.policy.overrides),
                     "policy_sha256":policy_hash,"filtering_enabled":status.filteringEnabled,"safe_mode":status.emergencySafeMode},
                    instance=policy.instanceId,revision=policy.revision))
            elif tool==ToolName.DEVICE:
                raw,received=await self.client.get("/v2/bindings"); bindings=parse_wire(Bindings,raw)
                groups={}
                for row in bindings.observations:
                    if row.validated and row.observedAtUtc<=received<row.expiresAtUtc and self._fresh(row.observedAtUtc,received):
                        groups.setdefault((row.address,row.networkScope),set()).add(row.deviceId)
                for row in bindings.observations[:8]:
                    state="stale" if not (row.observedAtUtc<=received<row.expiresAtUtc and self._fresh(row.observedAtUtc,received)) else "unvalidated" if not row.validated else "ambiguous" if len(groups.get((row.address,row.networkScope),()))>1 else "fresh_reported"
                    evidence.append(self._evidence(tool,"/v2/bindings",received,"binding_status",
                        {"address":row.address,"api_validated":row.validated,"state":state,"generation":bindings.generation},
                        observed=row.observedAtUtc,valid_until=row.expiresAtUtc,network_scope=row.networkScope,device_id=row.deviceId,binding_state=state))
                if not evidence:
                    evidence.append(self._evidence(tool,"/v2/bindings",received,"binding_status",{"generation":bindings.generation,"state":"missing"},binding_state="missing"))
                available=any(e.binding_state=="fresh_reported" for e in evidence)
                code=None if available else "adapter:binding_missing" if not bindings.observations else "adapter:binding_unverified"
                return EngineToolResult(tool=tool,outcome=Outcome.SUCCESS if available else Outcome.INSUFFICIENT,evidence=tuple(evidence),reason_code=code,
                    limitation="No target device is resolved from the question; bindings are reported observations, not independently verified identity. At most 8 entries.")
            elif tool==ToolName.ACTIVITY:
                raw,received=await self.client.get("/v3/activity"); activity=parse_wire(Activity,raw)
                if any(bucket.windowStartUtc>activity.observedAtUtc or bucket.windowStartUtc<activity.observedAtUtc-timedelta(hours=24,minutes=5) for bucket in activity.buckets):
                    raise ValueError()
                evidence.append(self._evidence(tool,"/v3/activity",received,"activity_summary",
                    {"allowed":sum(b.allowed for b in activity.buckets),"blocked":sum(b.blocked for b in activity.buckets),
                     "failed":sum(b.failed for b in activity.buckets),"window_hours":24},observed=activity.observedAtUtc))
            else:
                raise EngineReadError(Outcome.INVALID,"adapter:operation_not_allowed")
            outcome=Outcome.INSUFFICIENT if any(e.freshness=="stale" for e in evidence) else Outcome.SUCCESS
            if outcome!=Outcome.SUCCESS:
                evidence=[e.model_copy(update={"verification":"unverified"}) for e in evidence]
            return EngineToolResult(tool=tool,outcome=outcome,evidence=tuple(evidence),reason_code="adapter:stale_data" if outcome==Outcome.INSUFFICIENT else None)
        except EngineReadError as exc:
            # Previously authenticated reads survive as partial evidence, not new success.
            safe=tuple(e.model_copy(update={"verification":"unverified"}) for e in evidence)
            return EngineToolResult(tool=tool,outcome=exc.outcome,evidence=safe,reason_code=exc.code,limitation="Read failed; underlying cause is not established.")
        except (ValueError,TypeError,KeyError):
            return EngineToolResult(tool=tool,outcome=Outcome.INVALID,reason_code="adapter:invalid_response",limitation="Engine response contract validation failed.")
